var BufferList = require('bl')
  , Transform = require('stream').Transform
  , inherits = require('util').inherits
  , uint = require('cuint').UINT32
  , cryptTable = require('./crypt-table')

var hashFileKey = require('./hashfuncs').hashFileKey
  , hashNameA = require('./hashfuncs').hashNameA
  , hashNameB = require('./hashfuncs').hashNameB
  , hashTableOffset = require('./hashfuncs').hashTableOffset

module.exports = function() {
  return new ScmExtractor()
}

var STATE_MAGIC = 1
  , STATE_HEADER_SIZE = 2
  , STATE_ARCHIVE_SIZE = 3
  , STATE_HEADER_CONTENTS = 4
  , STATE_BUFFERING_FILES = 5
  , STATE_STREAMING_FILES = 6
  , STATE_BLOCK_TABLE = 7
  , STATE_HASH_TABLE = 8
  , STATE_DONE = 9
  , STATE_ERROR = 666

inherits(ScmExtractor, Transform)
function ScmExtractor() {
  Transform.call(this)
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

ScmExtractor.prototype._transform = function(data, enc, done) {
  var oldLength = Infinity
    , self = this

  function process() {
    while (self._buffer.length < oldLength) {
      console.log('STATE: %d  Buffer: %d bytes', self._state, self._buffer.length)
      oldLength = self._buffer.length

      switch (self._state) {
        case STATE_MAGIC:
          self._readMagic()
          break
        case STATE_HEADER_SIZE:
          self._readHeaderSize()
          break
        case STATE_ARCHIVE_SIZE:
          self._readArchiveSize()
          break
        case STATE_HEADER_CONTENTS:
          self._readHeaderContents()
          break
        case STATE_BUFFERING_FILES:
          self._bufferFileList()
          break
        case STATE_STREAMING_FILES:
          self._streamFileList()
          break
        case STATE_BLOCK_TABLE:
          self._readBlockTable()
          break
        case STATE_HASH_TABLE:
          self._readHashTable()
          break
        case STATE_DONE:
          self._consume(self._buffer.length)
          break
      }
    }

    done()
  }

  this._buffer.append(data)
  process()
}

ScmExtractor.prototype._flush = function(done) {
  if (this._state != STATE_DONE) {
    done(new Error('Invalid SCM contents'))
  } else {
    done()
  }
}

ScmExtractor.prototype._error = function(msg) {
  this._state = STATE_ERROR
  this.emit('error', new Error(msg))
}

ScmExtractor.prototype._consume = function(bytes) {
  this._offset += bytes
  this._buffer.consume(bytes)
}

var MAGIC = 'MPQ\x1A'
ScmExtractor.prototype._readMagic = function() {
  if (this._buffer.length < 4) return

  if (this._buffer.toString('ascii', 0, 4) != MAGIC) {
    return this._error('Invalid SCM header')
  }

  this._consume(4)
  this._state = STATE_HEADER_SIZE
}

ScmExtractor.prototype._readHeaderSize = function() {
  if (this._buffer.length < 4) return

  this._headerSize = this._buffer.readUInt32LE(0)
  this._consume(4)

  if (this._headerSize < 32) {
    return this._error('Invalid header size')
  }

  this._state = STATE_ARCHIVE_SIZE
}

ScmExtractor.prototype._readArchiveSize = function() {
  if (this._buffer.length < 4) return

  this._archiveSize = this._buffer.readUInt32LE(0)
  this._consume(4)

  if (this._archiveSize < this._headerSize) {
    return this._error('Invalid header/archive size')
  }

  this._state = STATE_HEADER_CONTENTS
}

ScmExtractor.prototype._readHeaderContents = function() {
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
    return this._error('Invalid SCM format version: ' + this._header.formatVersion)
  }
  if (this._header.hashTableOffset >= this._archiveSize) {
    return this._error('Invalid SCM file, hash table offset past end of the archive')
  }
  if (this._header.blockTableOffset >= this._archiveSize) {
    return this._error('Invalid SCM file, block table offset past end of the archive')
  }

  console.dir(this._header)
  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else if (this._offset == this._header.hashTableOffset) {
    this._state = STATE_HASH_TABLE
  } else {
    this._state = STATE_BUFFERING_FILES
  }
}

ScmExtractor.prototype._bufferFileList = function() {
  var nextHashTable = this._header.hashTableOffset > this._offset ?
          this._header.hashTableOffset : Infinity
  var nextBlockTable = this._header.blockTableOffset > this._offset ?
          this._header.blockTableOffset : Infinity
  var nextTable = Math.min(nextHashTable, nextBlockTable)
    , tilNextTable = nextTable - this._offset
  if (this._buffer.length < tilNextTable) return

  this._fileDataOffset = this._offset
  this._bufferedFiles = this._buffer.slice(0, tilNextTable)
  this._consume(tilNextTable)

  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else {
    this._state = STATE_HASH_TABLE
  }
}

var HASH_TABLE_ENTRY_SIZE = 16
ScmExtractor.prototype._readHashTable = function() {
  var index = 0
    , d = this._hashDecrypter
  while (this._buffer.length - index > HASH_TABLE_ENTRY_SIZE &&
      this._hashTable.length < this._header.hashTableEntries) {
    var entry = {
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

  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else if (this._bufferedFiles && this._blockTable.length) {
    this._loadBufferedAndFinish()
  } else if (this._blockTable.length) {
    this._state = STATE_STREAMING_FILES
  } else {
    return this._error('Invalid SCM file, expected to encounter block table')
  }
}

var BLOCK_TABLE_ENTRY_SIZE = 16
ScmExtractor.prototype._readBlockTable = function() {
  var index = 0
    , d = this._blockDecrypter
  while (this._buffer.length - index > BLOCK_TABLE_ENTRY_SIZE &&
      this._blockTable.length < this._header.blockTableEntries) {
    var entry = {
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

  console.dir(this._blockTable)
  if (this._offset == this._header.hashTableOffset) {
    this._state = STATE_HASH_TABLE
  } else if (this._bufferedFiles && this._hashTable.length) {
    this._loadBufferedAndFinish()
  } else if (this._hashTable.length) {
    this._state = STATE_STREAMING_FILES
  } else {
    return this._error('Invalid SCM file, expected to encounter hash table')
  }
}

var FLAG_FILE = 0x80000000
  , FLAG_CHECKSUMS = 0x04000000
  , FLAG_DELETED = 0x02000000
  , FLAG_UNSECTORED = 0x01000000
  , FLAG_ADJUSTED_KEY = 0x00020000
  , FLAG_ENCRYPTED = 0x00010000
  , FLAG_COMPRESSED = 0x00000200
  , FLAG_IMPLODED = 0x00000100
var COMPRESSION_HUFFMAN = 0x01
  , COMPRESSION_IMPLODED = 0x08
var _1 = uint(1)
ScmExtractor.prototype._loadBufferedAndFinish = function() {
  var i

  var blockIndex = this._findBlockIndex()
  if (blockIndex < 0) {
    return this._error('Invalid SCM file, couldn\'t find CHK file in hash table')
  }
  if (blockIndex >= this._blockTable.length) {
    return this._error('Invalid SCM file, CHK blockIndex is invalid')
  }

  var block = this._blockTable[blockIndex]
    , fileOffset = this._fileDataOffset
    , fileData = this._bufferedFiles
  if (!(block.flags & FLAG_FILE) || (block.flags & FLAG_DELETED)) {
    return this._error('Invalid SCM file, CHK is deleted')
  }
  if (block.blockSize + block.offset > fileData.length) {
    return this._error('Invalid SCM file, CHK exceeds file data boundaries')
  }

  var sectorSize = 512 << this._header.sectorSizeShift

  var encrypted = block.flags & FLAG_ENCRYPTED || block.flags & FLAG_ADJUSTED_KEY
    , encryptionKey = encrypted ?
        calcEncryptionKey(CHK_NAME, block.offset, block.fileSize, block.flags) : undefined
    , d
  var numSectors = block.flags & FLAG_UNSECTORED ? 1 : Math.ceil(block.fileSize / sectorSize)
    , hasSectorOffsetTable = !((block.flags & FLAG_UNSECTORED) ||
          ((block.flags & FLAG_COMPRESSED === 0) && (block.flags & FLAG_IMPLODED === 0)))
  // TODO(tec27): deal with CRC

  var self = this
    , sectorOffsetTable = new Array(numSectors + 1)
    , blockOffset = block.offset - fileOffset
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
      sectorOffsetTable[i]
      if (sectorOffsetTable[i] > block.blockSize) {
        return this._error('Invalid SCM file, CHK sector ' + i + ' extends outside block')
      }
    }

    if (sectorOffsetTable[sectorOffsetTable.length - 1] != block.blockSize) {
      return this._error('Invalid SCM file, sector offsets don\'t match block size')
    }
  } else if (numSectors == 1) {
    sectorOffsetTable[0] = 0
    sectorOffsetTable[1] = block.blockSize
  } else {
    for (i = 0; i < sectorOffsetTable.length - 1; i++) {
      sectorOffsetTable[i] = i * sectorSize
    }
    sectorOffsetTable[i] = block.blockSize
  }

  // read the sectors woohoo
  for (i = 0; i < sectorOffsetTable.length - 1; i++ ) {
    var start = sectorOffsetTable[i] + blockOffset
      , compressionType = 0

    if (encrypted) d = new Decrypter(encryptionKey.add(_1).toNumber() >>> 0)
    if (block.flags & FLAG_COMPRESSED) {
      compressionType = this._bufferedFiles.readUInt8(start)
      if (encrypted) compressionType = d.decrypt(compressionType) & 0xFF
      start++
    }
    var sector = this._bufferedFiles.slice(start, sectorOffsetTable[i + 1] + blockOffset)
    // TODO(tec27): decompress
    // TODO(tec27): decrypt
    this.push(sector)
  }

  this._bufferedFiles = null
  this._hashTable = null
  this._blockTable = null
  this._state = STATE_DONE

  function calcEncryptionKey(filePath, blockOffset, fileSize, flags) {
    // only use the filename, ignore \'s
    filePath = filePath.substr(filePath.lastIndexOf('\\') + 1)
    var fileKey = hashFileKey(filePath)
    if (flags & FLAG_ADJUSTED_KEY) {
      return uint(fileKey).add(uint(blockOffset)).xor(uint(fileSize))
    }
    return uint(fileKey)
  }
}


var CHK_NAME = '(listfile)' //'staredit\\scenario.chk'
  , CHK_HASH_OFFSET = hashTableOffset(CHK_NAME)
  , CHK_NAME_A = hashNameA(CHK_NAME)
  , CHK_NAME_B = hashNameB(CHK_NAME)
ScmExtractor.prototype._findBlockIndex = function() {
  var b = CHK_HASH_OFFSET & (this._hashTable.length - 1)
    , i = b
  while (this._hashTable[i].blockIndex != 0xFFFFFFFF) {
    if (this._hashTable[i].blockIndex != 0xFFFFFFFE) {
      // not deleted
      var cur = this._hashTable[i]
      if (cur.hashA == CHK_NAME_A && cur.hashB == CHK_NAME_B) {
        return cur.blockIndex
      }
    }

    i = (i + 1) % this._hashTable.length
    if (b === i) break // don't loop around the hash table multiple times
  }

  return -1
}

function Decrypter(key) {
  this.key = uint(key)
  this.seed = uint(0xEEEEEEEE)
  this.log = key == hashFileKey('(block table)')
}

var _FF = uint(0xFF)
  , _11111111 = uint(0x11111111)
  , _3 = uint(3)
Decrypter.prototype.decrypt = function(u32) {
  var ch = uint(u32)
  this.seed.add(cryptTable[0x400 + this.key.clone().and(_FF).toNumber()])
  ch.xor(this.key.clone().add(this.seed))
  this.key = this.key.clone().not().shiftLeft(0x15).add(_11111111).or(
      this.key.clone().shiftRight(0x0B))
  this.seed.add(this.seed.clone().shiftLeft(5)).add(ch).add(_3)

  return ch.toNumber() >>> 0
}
