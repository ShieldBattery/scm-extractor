"use strict"; // eslint-disable-line quotes,semi

const BufferList = require('bl')
const Transform = require('stream').Transform
const uint = require('cuint').UINT32
const implodeDecoder = require('implode-decoder')
const streamSplicer = require('stream-splicer')
const cryptTable = require('./crypt-table')

const hashFileKey = require('./hashfuncs').hashFileKey
const hashNameA = require('./hashfuncs').hashNameA
const hashNameB = require('./hashfuncs').hashNameB
const hashTableOffset = require('./hashfuncs').hashTableOffset

const STATE_MAGIC = 1
const STATE_HEADER_SIZE = 2
const STATE_ARCHIVE_SIZE = 3
const STATE_HEADER_CONTENTS = 4
const STATE_BUFFERING_FILES = 5
const STATE_STREAMING_FILES = 6
const STATE_BLOCK_TABLE = 7
const STATE_HASH_TABLE = 8
const STATE_DONE = 9
const STATE_ERROR = 666

const FLAG_FILE = 0x80000000
const FLAG_DELETED = 0x02000000
const FLAG_UNSECTORED = 0x01000000
const FLAG_ADJUSTED_KEY = 0x00020000
const FLAG_ENCRYPTED = 0x00010000
const FLAG_COMPRESSED = 0x00000200
const FLAG_IMPLODED = 0x00000100

const _1 = uint(1)

const CHK_NAME = 'staredit\\scenario.chk'
const CHK_HASH_OFFSET = hashTableOffset(CHK_NAME)
const CHK_NAME_A = hashNameA(CHK_NAME)
const CHK_NAME_B = hashNameB(CHK_NAME)

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
    const output = new Buffer(dwordLength * 4)
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

const COMPRESSION_IMPLODED = 0x08
const DECOMPRESSORS = {}
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
      return done()
    }

    this.created = true
    const compressionType = block[0]
    if (!DECOMPRESSORS[compressionType]) {
      return this.emit('error', 'Unknown compression type: 0x' + compressionType.toString(16))
    }

    this.pipeline.splice(this.pipeline.indexOf(this) + 1, 0, DECOMPRESSORS[compressionType]())
    this.push(block.slice(1))
    done()
  }
}

class ScmExtractor extends Transform {
  constructor() {
    super()
    this._state = STATE_MAGIC
    this._buffer = new BufferList()

    this._offset = 0
    this._headerSize = -1
    this._archiveSize = -1
    this._header = {}
    this._fileDataOffset = -1
    this._bufferedFiles = null
    this._hashTable = []
    this._blockTable = []

    // TODO(tec27): implement streaming
    this._chkBlockIndex = -1
    this._chkBlockEntry = null

    this._hashDecrypter = new Decrypter(hashFileKey('(hash table)'))
    this._blockDecrypter = new Decrypter(hashFileKey('(block table)'))
  }

  _transform(data, enc, done) {
    let oldLength = Infinity
    this._buffer.append(data)

    while (this._buffer.length < oldLength) {
      oldLength = this._buffer.length

      switch (this._state) {
        case STATE_MAGIC:
          this._readMagic()
          break
        case STATE_HEADER_SIZE:
          this._readHeaderSize()
          break
        case STATE_ARCHIVE_SIZE:
          this._readArchiveSize()
          break
        case STATE_HEADER_CONTENTS:
          this._readHeaderContents()
          break
        case STATE_BUFFERING_FILES:
          this._bufferFileList()
          break
        case STATE_STREAMING_FILES:
          this._streamFileList()
          break
        case STATE_BLOCK_TABLE:
          this._readBlockTable()
          break
        case STATE_HASH_TABLE:
          this._readHashTable()
          break
        case STATE_DONE:
          this._consume(this._buffer.length)
          break
      }
    }

    done()
  }

  _flush(done) {
    if (this._state !== STATE_DONE) {
      done(new Error('Invalid SCM contents'))
    } else {
      done()
    }
  }

  _error(msg) {
    this._state = STATE_ERROR
    this.emit('error', new Error(msg))
  }

  _consume(bytes) {
    this._offset += bytes
    this._buffer.consume(bytes)
  }

  _readMagic() {
    if (this._buffer.length < 4) return

    const MAGIC = 'MPQ\x1A'
    if (this._buffer.toString('ascii', 0, 4) !== MAGIC) {
      this._error('Invalid SCM header')
      return
    }

    this._consume(4)
    this._state = STATE_HEADER_SIZE
  }

  _readHeaderSize() {
    if (this._buffer.length < 4) return

    this._headerSize = this._buffer.readUInt32LE(0)
    this._consume(4)

    if (this._headerSize < 32) {
      this._error('Invalid header size')
      return
    }

    this._state = STATE_ARCHIVE_SIZE
  }

  _readArchiveSize() {
    if (this._buffer.length < 4) return

    this._archiveSize = this._buffer.readUInt32LE(0)
    this._consume(4)

    if (this._archiveSize < this._headerSize) {
      this._error('Invalid header/archive size')
      return
    }

    this._state = STATE_HEADER_CONTENTS
  }

  _readHeaderContents() {
    if (this._buffer.length < this._headerSize - 12) return

    this._header.formatVersion = this._buffer.readInt16LE(0)
    this._header.sectorSizeShift = this._buffer.readUInt8(2)
    // 1 byte is skipped here
    this._header.hashTableOffset = this._buffer.readUInt32LE(4)
    this._header.blockTableOffset = this._buffer.readUInt32LE(8)
    this._header.hashTableEntries = this._buffer.readUInt32LE(12)
    this._header.blockTableEntries = this._buffer.readUInt32LE(16)

    this._consume(this._headerSize - 12)

    if (this._header.formatVersion !== 0) {
      this._error('Invalid SCM format version: ' + this._header.formatVersion)
      return
    }
    if (this._header.hashTableOffset >= this._archiveSize) {
      this._error('Invalid SCM file, hash table offset past end of the archive')
      return
    }
    if (this._header.blockTableOffset >= this._archiveSize) {
      this._error('Invalid SCM file, block table offset past end of the archive')
      return
    }

    if (this._offset === this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else if (this._offset === this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    } else {
      this._state = STATE_BUFFERING_FILES
    }
  }

  _bufferFileList() {
    const nextHashTable = this._header.hashTableOffset > this._offset ?
            this._header.hashTableOffset : Infinity
    const nextBlockTable = this._header.blockTableOffset > this._offset ?
            this._header.blockTableOffset : Infinity
    const nextTable = Math.min(nextHashTable, nextBlockTable)
    const tilNextTable = nextTable - this._offset
    if (this._buffer.length < tilNextTable) return

    this._fileDataOffset = this._offset
    this._bufferedFiles = this._buffer.slice(0, tilNextTable)
    this._consume(tilNextTable)

    if (this._offset === this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else {
      this._state = STATE_HASH_TABLE
    }
  }

  _readHashTable() {
    const HASH_TABLE_ENTRY_SIZE = 16

    let index = 0
    const d = this._hashDecrypter
    while (this._buffer.length - index >= HASH_TABLE_ENTRY_SIZE &&
        this._hashTable.length < this._header.hashTableEntries) {
      const entry = {
        hashA: d.decrypt(this._buffer.readUInt32LE(index)),
        hashB: d.decrypt(this._buffer.readUInt32LE(index + 4)),
        // we don't care about language or platform, but need to decrypt it to be able to decrypt
        // further fields/entries, so we just decrypt it into a combined field here
        langPlatform: d.decrypt(this._buffer.readUInt32LE(index + 8)),
        blockIndex: d.decrypt(this._buffer.readUInt32LE(index + 12))
      }
      this._hashTable.push(entry)
      index += HASH_TABLE_ENTRY_SIZE
    }

    this._consume(index)

    if (this._hashTable.length < this._header.hashTableEntries) return

    if (this._offset === this._header.blockTableOffset) {
      this._state = STATE_BLOCK_TABLE
    } else if (this._bufferedFiles && this._blockTable.length) {
      this._loadBufferedAndFinish()
    } else if (this._blockTable.length) {
      this._state = STATE_STREAMING_FILES
    } else {
      this._error('Invalid SCM file, expected to encounter block table')
      return
    }
  }

  _readBlockTable() {
    const BLOCK_TABLE_ENTRY_SIZE = 16

    let index = 0
    const d = this._blockDecrypter
    while (this._buffer.length - index >= BLOCK_TABLE_ENTRY_SIZE &&
        this._blockTable.length < this._header.blockTableEntries) {
      const entry = {
        offset: d.decrypt(this._buffer.readUInt32LE(index)),
        blockSize: d.decrypt(this._buffer.readUInt32LE(index + 4)),
        fileSize: d.decrypt(this._buffer.readUInt32LE(index + 8)),
        flags: d.decrypt(this._buffer.readUInt32LE(index + 12))
      }
      this._blockTable.push(entry)
      index += BLOCK_TABLE_ENTRY_SIZE
    }

    this._consume(index)

    if (this._blockTable.length < this._header.blockTableEntries) return

    if (this._offset === this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    } else if (this._bufferedFiles && this._hashTable.length) {
      this._loadBufferedAndFinish()
    } else if (this._hashTable.length) {
      this._state = STATE_STREAMING_FILES
    } else {
      this._error('Invalid SCM file, expected to encounter hash table')
      return
    }
  }

  _loadBufferedAndFinish() {
    let i

    // since this function can be async, we set the state to DONE here so that discards happen if
    // any data comes in in the intermediate. At worst, our state will later become ERROR
    this._state = STATE_DONE

    const blockIndex = this._findBlockIndex()
    if (blockIndex < 0) {
      return this._error('Invalid SCM file, couldn\'t find CHK file in hash table')
    }
    if (blockIndex >= this._blockTable.length) {
      return this._error('Invalid SCM file, CHK blockIndex is invalid')
    }

    const block = this._blockTable[blockIndex]
    const fileOffset = this._fileDataOffset
    const fileData = this._bufferedFiles
    if (!(block.flags & FLAG_FILE) || (block.flags & FLAG_DELETED)) {
      return this._error('Invalid SCM file, CHK is deleted')
    }
    if (block.blockSize + block.offset > fileData.length) {
      return this._error('Invalid SCM file, CHK exceeds file data boundaries')
    }

    const sectorSize = 512 << this._header.sectorSizeShift

    const encrypted = block.flags & FLAG_ENCRYPTED || block.flags & FLAG_ADJUSTED_KEY
    const encryptionKey = encrypted ?
        calcEncryptionKey(CHK_NAME, block.offset, block.fileSize, block.flags) : undefined
    let d
    const numSectors = block.flags & FLAG_UNSECTORED ? 1 : Math.ceil(block.fileSize / sectorSize)
    const hasSectorOffsetTable = !((block.flags & FLAG_UNSECTORED) ||
        ((block.flags & FLAG_COMPRESSED === 0) && (block.flags & FLAG_IMPLODED === 0)))

    const sectorOffsetTable = new Array(numSectors + 1)
    const blockOffset = block.offset - fileOffset
    if (encrypted) {
      encryptionKey.subtract(_1)
    }
    if (hasSectorOffsetTable) {
      if (encrypted) d = new Decrypter(encryptionKey.toNumber() >>> 0)
      for (i = 0; i < sectorOffsetTable.length; i++) {
        sectorOffsetTable[i] = fileData.readUInt32LE(blockOffset + i * 4)
        if (encrypted) {
          sectorOffsetTable[i] = d.decrypt(sectorOffsetTable[i])
        }
        if (sectorOffsetTable[i] > block.blockSize) {
          return this._error('Invalid SCM file, CHK sector ' + i + ' extends outside block')
        }
      }

      if (sectorOffsetTable[sectorOffsetTable.length - 1] !== block.blockSize) {
        return this._error('Invalid SCM file, sector offsets don\'t match block size')
      }
    } else if (numSectors === 1) {
      sectorOffsetTable[0] = 0
      sectorOffsetTable[1] = block.blockSize
    } else {
      for (i = 0; i < sectorOffsetTable.length - 1; i++) {
        sectorOffsetTable[i] = i * sectorSize
      }
      sectorOffsetTable[i] = block.blockSize
    }

    const done = () => {
      this._bufferedFiles = null
      this._hashTable = null
      this._blockTable = null
    }

    let fileSizeLeft = block.fileSize
    const processSector = i => {
      const next = () => {
        if (i < sectorOffsetTable.length - 1) {
          processSector(i + 1)
        } else {
          done()
        }
      }

      const start = sectorOffsetTable[i] + blockOffset
      const curSectorSize = sectorOffsetTable[i + 1] - sectorOffsetTable[i]
      const sectorCompressed = block.flags & FLAG_COMPRESSED &&
          !(curSectorSize >= sectorSize || curSectorSize === fileSizeLeft)

      const sector = this._bufferedFiles.slice(start, sectorOffsetTable[i + 1] + blockOffset)
      if (!encrypted && !sectorCompressed) {
        // this sector can be written directly to the output stream!
        fileSizeLeft -= curSectorSize
        this.push(sector)
        return next()
      }

      const pipeline = streamSplicer()
      if (encrypted) {
        pipeline.push(new DecrypterStream(encryptionKey.add(_1).toNumber() >>> 0))
      }
      if (sectorCompressed) {
        pipeline.push(new DecompressorStream(pipeline))
      }

      pipeline.pipe(new BufferList((err, buf) => {
        if (err) {
          return this._error(`Invalid SCM file, error extracting CHK file sector ${i}: ${err}`)
        }

        fileSizeLeft -= buf.length
        this.push(buf)
        next()
      }))
      pipeline.end(sector)
    }
    processSector(0)
  }

  _findBlockIndex() {
    const b = CHK_HASH_OFFSET & (this._hashTable.length - 1)
    let i = b
    while (this._hashTable[i].blockIndex !== 0xFFFFFFFF) {
      if (this._hashTable[i].blockIndex !== 0xFFFFFFFE) {
        // not deleted
        const cur = this._hashTable[i]
        if (cur.hashA === CHK_NAME_A && cur.hashB === CHK_NAME_B) {
          return cur.blockIndex
        }
      }

      i = (i + 1) % this._hashTable.length
      if (b === i) break // don't loop around the hash table multiple times
    }

    return -1
  }
}

module.exports = function() {
  return new ScmExtractor()
}
