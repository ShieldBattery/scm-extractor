"use strict"; // eslint-disable-line quotes,semi

const BufferList = require('bl')
const Transform = require('stream').Transform
const uint = require('cuint').UINT32
const implodeDecoder = require('implode-decoder')
const streamSplicer = require('stream-splicer')
const zlib = require('zlib')
const cryptTable = require('./crypt-table')

const hashFileKey = require('./hashfuncs').hashFileKey
const hashNameA = require('./hashfuncs').hashNameA
const hashNameB = require('./hashfuncs').hashNameB
const hashTableOffset = require('./hashfuncs').hashTableOffset

const STATE_FIND_HEADER = 1
const STATE_HEADER_CONTENTS = 3
const STATE_WAITING_FOR_TABLES = 4
const STATE_BLOCK_TABLE = 5
const STATE_HASH_TABLE = 6
const STATE_READING_FILES = 7
const STATE_DONE = 8
const STATE_ERROR = 666

const FLAG_FILE = 0x80000000
const FLAG_DELETED = 0x02000000
const FLAG_ADJUSTED_KEY = 0x00020000
const FLAG_ENCRYPTED = 0x00010000
const FLAG_COMPRESSED = 0x00000200
const FLAG_IMPLODED = 0x00000100

const _1 = uint(1)

const CHK_NAME = 'staredit\\scenario.chk'
const CHK_HASH_OFFSET = hashTableOffset(CHK_NAME)
const CHK_NAME_A = hashNameA(CHK_NAME)
const CHK_NAME_B = hashNameB(CHK_NAME)
const CHK_LANG_PLATFORM = 0x00000000

function calcEncryptionKey(filePath, blockOffset, fileSize, flags) {
  // only use the filename, ignore folders and \'s
  filePath = filePath.substr(filePath.lastIndexOf('\\') + 1)
  const fileKey = hashFileKey(filePath)
  if (flags & FLAG_ADJUSTED_KEY) {
    return uint(fileKey).add(uint(blockOffset)).xor(uint(fileSize))
  }
  return uint(fileKey)
}

const _FF = uint(0xFF)
const _11111111 = uint(0x11111111)
const _3 = uint(3)

class Decrypter {
  constructor(key) {
    this.key = uint(key)
    this.seed = uint(0xEEEEEEEE)
  }

  decrypt(u32) {
    const ch = uint(u32)
    this.seed.add(cryptTable[0x400 + this.key.clone().and(_FF).toNumber()])
    ch.xor(this.key.clone().add(this.seed))
    this.key = this.key.clone().not().shiftLeft(0x15).add(_11111111).or(
        this.key.clone().shiftRight(0x0B))
    this.seed.add(this.seed.clone().shiftLeft(5)).add(ch).add(_3)

    return ch.toNumber() >>> 0
  }

  decryptSigned(u32) {
    const val = this.decrypt(u32)
    if (val >= 0x80000000) {
      return 0 - ~val - 1
    } else {
      return val
    }
  }
}

class DecrypterStream extends Transform {
  constructor(key) {
    super()
    this.decrypter = new Decrypter(key)
    this.buffer = new BufferList()
  }

  _transform(block, enc, done) {
    this.buffer.append(block)

    const dwordLength = this.buffer.length >> 2
    const output = Buffer.allocUnsafe(dwordLength * 4)
    for (let i = 0; i < dwordLength; i++) {
      output.writeUInt32LE(this.decrypter.decrypt(this.buffer.readUInt32LE(i * 4)), i * 4)
    }
    this.push(output)
    this.buffer.consume(dwordLength * 4)
    done()
  }

  _flush(done) {
    this.push(this.buffer.slice(0))
    done()
  }
}

const COMPRESSION_DEFLATED = 0x02
const COMPRESSION_IMPLODED = 0x08
const DECOMPRESSORS = {}
DECOMPRESSORS[COMPRESSION_DEFLATED] = zlib.createInflate
DECOMPRESSORS[COMPRESSION_IMPLODED] = implodeDecoder

class DecompressorStream extends Transform {
  constructor(pipeline) {
    super()
    this.pipeline = pipeline
    this.created = false
  }

  _transform(block, enc, done) {
    if (this.created) {
      this.push(block)
      done()
      return
    }

    this.created = true
    const compressionType = block[0]
    if (!DECOMPRESSORS[compressionType]) {
      this.emit('error', 'Unknown compression type: 0x' + compressionType.toString(16))
      return
    }

    this.pipeline.splice(this.pipeline.indexOf(this) + 1, 0, DECOMPRESSORS[compressionType]())
    this.push(block.slice(1))
    done()
  }
}

// Since MPQs can be embedded in other files, there can be valid data before the MPQ header.
// Unsurprisingly, Storm happily accepts any "negative offsets", so we'll use this FileBuffer,
// which behaves like BufferList but allows accessing negative offsets if the offset doesn't
// underflow the file buffer. Also provides `minimumOffset()` for checking the smallest valid
// offset.
class FileBuffer {
  constructor() {
    this._buf = new BufferList()
    this._offset = 0
    this.length = 0
  }

  minimumOffset() {
    return 0 - this._offset
  }

  toString(enc, start, end) {
    return this._buf.toString(enc, this._offset + start, this._offset + end)
  }

  append(data) {
    this._buf.append(data)
    this.length += data.length
  }

  consume(len) {
    this._offset += len
    this.length -= len
  }

  slice(start, end) {
    return this._buf.slice(this._offset + start, this._offset + end)
  }

  readUInt8(offset) {
    return this._buf.readUInt8(this._offset + offset)
  }

  readUInt16LE(offset) {
    return this._buf.readUInt16LE(this._offset + offset)
  }

  readUInt32LE(offset) {
    return this._buf.readUInt32LE(this._offset + offset)
  }

  readInt32LE(offset) {
    return this._buf.readInt32LE(this._offset + offset)
  }
}

class ScmExtractor extends Transform {
  constructor() {
    super()
    this._state = STATE_FIND_HEADER
    this._buffer = new FileBuffer()
    this._flushed = false

    // The offset of the buffer from the beginning of the file
    this._absoluteOffset = 0
    this._header = {
      sectorSizeShift: 0,
      hashTableOffset: 0,
      blockTableOffset: 0,
      hashTableEntries: 0,
      blockTableEntries: 0,
    }
    this._hasReadHashTable = false
    this._hashTable = []
    this._hasReadBlockTable = false
    this._blockTable = []

    this._chkBlockIndex = -1
    this._readingFiles = false
    this._flushCb = null

    this._hashDecrypter = new Decrypter(hashFileKey('(hash table)'))
    this._blockDecrypter = new Decrypter(hashFileKey('(block table)'))
  }

  _process() {
    let oldOffset = -1
    let oldState = -1

    while (this._absoluteOffset > oldOffset || this._state !== oldState) {
      oldOffset = this._absoluteOffset
      oldState = this._state

      switch (this._state) {
        case STATE_FIND_HEADER:
          this._findHeader()
          break
        case STATE_HEADER_CONTENTS:
          this._readHeaderContents()
          break
        case STATE_WAITING_FOR_TABLES:
          this._waitForTables()
          break
        case STATE_READING_FILES:
          this._readFiles()
          break
        case STATE_BLOCK_TABLE:
          this._readBlockTable()
          break
        case STATE_HASH_TABLE:
          this._readHashTable()
          break
        case STATE_DONE:
          break
      }
    }
  }

  _transform(data, enc, done) {
    if (this._state !== STATE_DONE) {
      this._buffer.append(data)
      this._process()
    }
    done()
  }

  _flush(done) {
    this._flushed = true
    if (this._state !== STATE_DONE) {
      this._process()
    }

    if (this._state !== STATE_DONE) {
      done(new Error('Invalid SCM contents'))
    } else {
      if (!this._readingFiles) {
        done()
      } else {
        // We're currently reading files (async-ly). Just save the callback and let that process
        // call it
        this._flushCb = done
      }
    }
  }

  _error(msg) {
    this._state = STATE_ERROR
    this.emit('error', new Error(msg))
  }

  _discard(bytes) {
    this._absoluteOffset += bytes
    this._buffer.consume(bytes)
  }

  _findHeader() {
    // MPQs are allowed to not start at the beginning of a file, but must always start on a
    // 512 multiple. If we're offset from 512, it means we didn't find the magic in the previous
    // 512-sized block, so we're discarding to the next multiple
    if (this._absoluteOffset % 512 !== 0) {
      const needToDiscard = 512 - (this._absoluteOffset % 512)
      if (this._buffer.length <= needToDiscard) {
        this._discard(this._buffer.length)
        return
      } else {
        this._discard(needToDiscard)
      }
    }
    if (this._buffer.length < 8) return

    const headerSize = this._buffer.readUInt32LE(4)
    const MAGIC = 'MPQ\x1A'
    if (this._buffer.toString('ascii', 0, 4) === MAGIC && headerSize >= 32) {
      // Storm doesn't care if the header is bigger than 32 bytes, as long as its not smaller. It
      // never reads in *more* than 32 bytes of the header, though. Additionally, too small
      // headers only cause Storm to keep searching for the start of the MPQ.
      this._state = STATE_HEADER_CONTENTS
    } else {
      this._discard(8)
    }
  }

  _readHeaderContents() {
    if (this._buffer.length < 32) return

    this._header.sectorSizeShift = this._buffer.readUInt8(14)
    this._header.hashTableOffset = this._buffer.readInt32LE(16)
    if (this._header.hashTableOffset < this._buffer.minimumOffset()) {
      this._error('Invalid hash table offset')
      return
    }
    this._header.blockTableOffset = this._buffer.readInt32LE(20)
    if (this._header.blockTableOffset < this._buffer.minimumOffset()) {
      this._error('Invalid block table offset')
      return
    }
    // Discard high 4 bits of hashTableEntries, as C code multiplying that u32 by
    // hash table entry size (0x10) will cause them to overflow out of u32 range.
    this._header.hashTableEntries = this._buffer.readUInt32LE(24) & 0x0FFFFFFF
    this._header.blockTableEntries = this._buffer.readUInt32LE(28)

    // Notes:
    // - BW's Storm does not care in the least about formatVersion
    // - BW's Storm does not care in the least about archiveSize (so we can't use it for validation)

    if (this._buffer.length >= this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else if (this._buffer.length >= this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    } else {
      this._state = STATE_WAITING_FOR_TABLES
    }
  }

  _waitForTables() {
    if (!this._hasReadBlockTable && this._buffer.length >= this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else if (!this._hasReadHashTable && this._buffer.length >= this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    }
    // Otherwise, state stays the same, wait for more data
  }

  _readHashTable() {
    const HASH_TABLE_ENTRY_SIZE = 16

    this._hasReadHashTable = true
    let offset = this._header.hashTableOffset + this._hashTable.length * HASH_TABLE_ENTRY_SIZE
    const d = this._hashDecrypter
    while (this._buffer.length - offset >= HASH_TABLE_ENTRY_SIZE &&
        this._hashTable.length < this._header.hashTableEntries) {
      const entry = {
        hashA: d.decrypt(this._buffer.readUInt32LE(offset)),
        hashB: d.decrypt(this._buffer.readUInt32LE(offset + 4)),
        // we don't care about language or platform, but need to decrypt it to be able to decrypt
        // further fields/entries, so we just decrypt it into a combined field here
        langPlatform: d.decrypt(this._buffer.readUInt32LE(offset + 8)) & 0x00FFFFFF,
        blockIndex: d.decrypt(this._buffer.readUInt32LE(offset + 12))
      }
      this._hashTable.push(entry)
      offset += HASH_TABLE_ENTRY_SIZE
    }

    // Storm is cool with the hash table being cut off by the end of the file, so we are too. If
    // _flushed is set, we're at the end, so ignore the fact that we don't have enough entries
    if (!this._flushed && this._hashTable.length < this._header.hashTableEntries) return

    if (!this._hasReadBlockTable && this._buffer.length >= this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else if (this._hasReadBlockTable) {
      this._state = STATE_READING_FILES
    } else {
      this._state = STATE_WAITING_FOR_TABLES
    }
  }

  _readBlockTable() {
    const BLOCK_TABLE_ENTRY_SIZE = 16

    this._hasReadBlockTable = true
    let offset = this._header.blockTableOffset + this._blockTable.length * BLOCK_TABLE_ENTRY_SIZE
    const d = this._blockDecrypter
    while (this._buffer.length - offset >= BLOCK_TABLE_ENTRY_SIZE &&
        this._blockTable.length < this._header.blockTableEntries) {
      const entry = {
        offset: d.decryptSigned(this._buffer.readUInt32LE(offset)),
        blockSize: d.decrypt(this._buffer.readUInt32LE(offset + 4)),
        fileSize: d.decrypt(this._buffer.readUInt32LE(offset + 8)),
        flags: d.decrypt(this._buffer.readUInt32LE(offset + 12))
      }
      this._blockTable.push(entry)
      offset += BLOCK_TABLE_ENTRY_SIZE
    }


    // Storm is cool with the block table being cut off by the end of the file, so we are too. If
    // _flushed is set, we're at the end, so ignore the fact that we don't have enough entries
    if (!this._flushed && this._blockTable.length < this._header.blockTableEntries) return

    if (!this._hasReadHashTable && this._offset === this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    } else if (this._hasReadHashTable) {
      this._state = STATE_READING_FILES
    } else {
      this._state = STATE_WAITING_FOR_TABLES
    }
  }

  _readSectorOffsetTable(block, encrypted, encryptionKey) {
    const sectorSize = 512 << this._header.sectorSizeShift
    let d
    const numSectors = Math.ceil(block.fileSize / sectorSize)
    // Unless the file is unsectored, or its fileSize is the same as its total sector size, it has
    // a sector offset table
    const hasSectorOffsetTable = block.flags & (FLAG_COMPRESSED | FLAG_IMPLODED)

    const sectorOffsetTable = new Array(numSectors + 1)

    if (hasSectorOffsetTable) {
      if (this._buffer.length < sectorOffsetTable.length * 4) {
        // Can happen if we're flushed while trying to read file data
        this._error('Invalid SCM file, unexpected end in sector offset table')
        return null
      }

      if (encrypted) d = new Decrypter(encryptionKey.toNumber() >>> 0)
      for (let i = 0; i < sectorOffsetTable.length; i++) {
        if (encrypted) {
          const val = this._buffer.readUInt32LE(block.offset + i * 4)
          sectorOffsetTable[i] = d.decryptSigned(val)
        } else {
          sectorOffsetTable[i] = this._buffer.readInt32LE(block.offset + i * 4)
        }
        if (sectorOffsetTable[i] > block.blockSize) {
          this._error('Invalid SCM file, CHK sector ' + i + ' extends outside block')
          return null
        }

        if (i > 0 && sectorOffsetTable[i - 1] > sectorOffsetTable[i]) {
          this._error(`Invalid SCM file, CHK sector ${i} starts at an earlier offset ` +
              'than the previous one')
          return null
        }
      }
    } else if (numSectors === 1) {
      sectorOffsetTable[0] = 0
      sectorOffsetTable[1] = block.blockSize
    } else {
      for (let i = 0; i < sectorOffsetTable.length - 1; i++) {
        sectorOffsetTable[i] = i * sectorSize
      }
      sectorOffsetTable[sectorOffsetTable.length - 1] = block.blockSize
    }

    return sectorOffsetTable
  }

  _readFiles() {
    if (this._chkBlockIndex < 0) {
      this._chkBlockIndex = this._findBlockIndex()
      if (this._chkBlockIndex < 0) {
        this._error('Invalid SCM file, couldn\'t find CHK file in hash table')
        return
      }
      if (this._chkBlockIndex >= this._blockTable.length) {
        this._error('Invalid SCM file, CHK block index is invalid')
        return
      }
    }

    const block = this._blockTable[this._chkBlockIndex]
    if (!(block.flags & FLAG_FILE) || (block.flags & FLAG_DELETED)) {
      this._error('Invalid SCM file, CHK is deleted')
      return
    }
    // Storm is cool with the file data being cut off by the end of the file, so we are too. If
    // _flushed is set, we're at the end, so ignore the fact that we don't have enough bytes
    if (!this._flushed && block.blockSize + block.offset > this._buffer.length) {
      // Not enough data yet
      return
    }

    this._readBufferedFileData()
  }

  _readBufferedFileData() {
    // Since the reading parts of this function can be async, we set the state to DONE here so that
    // discards happen if any data comes in in the intermediate. At worst, our state will later
    // become ERROR
    this._state = STATE_DONE

    const block = this._blockTable[this._chkBlockIndex]
    const encrypted = block.flags & FLAG_ENCRYPTED || block.flags & FLAG_ADJUSTED_KEY
    const encryptionKey = encrypted ?
        calcEncryptionKey(CHK_NAME, block.offset, block.fileSize, block.flags) : undefined
    if (encrypted) {
      encryptionKey.subtract(_1)
    }

    const sectorOffsetTable = this._readSectorOffsetTable(block, encrypted, encryptionKey)

    if (!sectorOffsetTable) {
      // An error happened while reading the sector offset table
      return
    }

    const done = () => {
      this._buffer = null
      this._hashTable = null
      this._blockTable = null
      this._readingFiles = false
      if (this._flushCb) {
        this._flushCb()
        this._flushCb = null
      }
    }

    const sectorSize = 512 << this._header.sectorSizeShift
    let fileSizeLeft = block.fileSize
    const processSector = i => {
      const next = () => {
        if (i + 1 < sectorOffsetTable.length - 1) {
          processSector(i + 1)
        } else {
          done()
        }
      }

      const start = sectorOffsetTable[i] + block.offset
      if (start >= this._buffer.length || start < this._buffer.minimumOffset()) {
        // Can happen if we're flushed and this file is cut off. Not an error condition (Storm is
        // cool with it, so we are too).
        done()
        return
      }

      const curSectorSize = sectorOffsetTable[i + 1] - sectorOffsetTable[i]
      const useCompression = curSectorSize < sectorSize && curSectorSize < fileSizeLeft
      const sectorCompressed = (block.flags & FLAG_COMPRESSED) && useCompression
      const sectorImploded = (block.flags & FLAG_IMPLODED) && useCompression

      const sector = this._buffer.slice(start, start + curSectorSize)
      if (!encrypted && !sectorCompressed && !sectorImploded) {
        // this sector can be written directly to the output stream!
        fileSizeLeft -= curSectorSize
        this.push(sector)
        next()
        return
      }

      const isLastSector = i === sectorOffsetTable.length - 2
      const onData = (err, buf) => {
        if (err) {
          this._error(`Invalid SCM file, error extracting CHK file sector ${i}: ${err}`)
          return
        }

        let toPush = buf
        if (toPush.length < sectorSize && !isLastSector) {
          // Storm expects that every decompression will result in sectorSize bytes of data (except,
          // possibly, for the very last sector). This is never verified, however, which means map
          // protection schemes can compress less data. When reading it back out, Storm will always
          // give sectorSize bytes anyway, so we need to pad the buffer in those cases.
          toPush = Buffer.alloc(sectorSize, 0)
          buf.copy(toPush)
        }
        fileSizeLeft -= toPush.length
        this.push(toPush)
        next()
      }
      this._createFileSectorPipeline(
        encrypted, encryptionKey, sectorCompressed, sectorImploded, onData).end(sector)
    }
    this._readingFiles = true
    processSector(0)
  }

  _createFileSectorPipeline(encrypted, encryptionKey, sectorCompressed, sectorImploded, cb) {
    const pipeline = streamSplicer()
    if (encrypted) {
      pipeline.push(new DecrypterStream(encryptionKey.add(_1).toNumber() >>> 0))
    }
    if (sectorCompressed) {
      pipeline.push(new DecompressorStream(pipeline))
    } else if (sectorImploded) {
      pipeline.push(implodeDecoder())
    }
    pipeline.pipe(new BufferList(cb))

    return pipeline
  }

  _findBlockIndex() {
    let b = CHK_HASH_OFFSET & (this._header.hashTableEntries - 1)
    if (b < this._hashTable.length && this._hashTable[b].blockIndex === 0xFFFFFFFF) {
      // table entry is empty
      return -1
    }

    // Certain protections can cause us to have less hash table entries than the header dictates.
    // In such cases, we still need to calculate the initial position with the "total" number of
    // entries, but the later entries aren't in our array. If we land outside of our array, skip
    // back to the front.
    if (b >= this._hashTable.length) {
      b = 0
    }
    let i = b
    // Storm will prefer entries that match the current language over 'default' ones. Thus, for
    // things like CHKs (which are generally default-only), it will iterate the entire table and
    // return the *last* matching entry, instead of the first as you might expect. Some protections
    // abuse this, so we do it the same as Storm.
    let index = -1
    do {
      if (this._hashTable[i].blockIndex !== 0xFFFFFFFE) {
        // not deleted
        const cur = this._hashTable[i]
        if (cur.hashA === CHK_NAME_A && cur.hashB === CHK_NAME_B &&
            cur.langPlatform === CHK_LANG_PLATFORM) {
          // Mask out high bits that will overflow out when doing uint32 multiplication by 0x10
          index = cur.blockIndex & 0x0FFFFFFF
        }
      }

      i = (i + 1) % this._hashTable.length
    } while (b !== i) // don't loop around the hash table multiple times

    return index
  }
}

module.exports = function() {
  return new ScmExtractor()
}
