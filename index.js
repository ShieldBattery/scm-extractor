var BufferList = require('bl')
  , Transform = require('stream').Transform
  , inherits = require('util').inherits
  , cryptTable = require('./crypt-table')

module.exports = function() {
  return new ScmExtractor()
}

var STATE_MAGIC = 1
  , STATE_HEADER_SIZE = 2
  , STATE_ARCHIVE_SIZE = 3
  , STATE_HEADER_CONTENTS = 4
  , STATE_BUFFERING_FILES = 5
  , STATE_BLOCK_TABLE = 6
  , STATE_HASH_TABLE = 7
  , STATE_STREAMING_DISCARD = 8
  , STATE_STREAMING_CHK = 9
  , STATE_DISCARD_REST = 11
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
  this._bufferedFiles = null
  this._bufferedBlockEntries = null

  this._chkBlockIndex = -1
  this._chkBlockEntry = null
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
        case STATE_BLOCK_TABLE:
          self._readBlockTable()
          break
        case STATE_HASH_TABLE:
          self._readHashTable()
          break
        case STATE_STREAMING_DISCARD:
        case STATE_STREAMING_CHK:
        case STATE_DISCARD_REST:
          break
      }
    }

    done()
  }

  this._buffer.append(data)
  process()
}

ScmExtractor.prototype._flush = function(done) {
  if (this._state != STATE_DISCARD_REST) {
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
  console.log('\noffset: ' + this._offset)
  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else if (this._offset == this._header.hashTableOffset) {
    this._state = STATE_HASH_TABLE
  } else {
    this._state = STATE_BUFFERING_FILES
  }
}

ScmExtractor.prototype._bufferFileList = function() {
  // TODO(tec27): Deal with the case that the layout is HT FD BT
  var nextTable = Math.min(this._header.hashTableOffset, this._header.blockTableOffset)
    , tilNextTable = nextTable - this._offset
  if (this._buffer.length < tilNextTable) return

  this._bufferedFiles = this._buffer.slice(0, tilNextTable)
  this._consume(tilNextTable)

  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else {
    this._state = STATE_HASH_TABLE
  }
}

var HASH_TABLE_ENTRY_SIZE = 16
  , CHK_NAME = 'staredit\\scenario.chk'
  , CHK_HASH_OFFSET = hashTableOffset(CHK_NAME)
  , CHK_NAME_A = hashNameA(CHK_NAME)
  , CHK_NAME_B = hashNameB(CHK_NAME)
ScmExtractor.prototype._readHashTable = function() {
  if (this._buffer.length < this._header.hashTableEntries * HASH_TABLE_ENTRY_SIZE) return

  var initOffset =
      (CHK_HASH_OFFSET & (this._header.hashTableEntries - 1)) * HASH_TABLE_ENTRY_SIZE
  var byteOffset = initOffset
  console.log('byteOffset: %d  hashA: %d', byteOffset, CHK_NAME_A)
  while (true) {
    var hashA = this._buffer.readUInt32LE(byteOffset)
      , hashB = this._buffer.readUInt32LE(byteOffset + 4)
      , fileBlockIndex = this._buffer.readUInt32LE(byteOffset + 12)
    console.log('checking byteOffset: %d  hashA: %d', byteOffset, hashA)
    if (hashA != CHK_NAME_A || hashB != CHK_NAME_B) {
      if (fileBlockIndex == 0xFFFFFFFF) {
        return this._error('Invaid SCM file, no CHK file found')
      }
      byteOffset += HASH_TABLE_ENTRY_SIZE
      if (byteOffset >= this._header.hashTableEntries * HASH_TABLE_ENTRY_SIZE) {
        byteOffset = 0
      }
      // make sure we don't infinitely loop around the hash table
      if (byteOffset == initOffset) {
        return this._error('Invalid SCM file, no CHK file found')
      }
      continue
    }

    this._chkBlockIndex = fileBlockIndex
    break
  }

  this._consume(this._header.hashTableEntries * HASH_TABLE_ENTRY_SIZE)

  if (this._offset == this._header.blockTableOffset) {
    this._state = STATE_BLOCK_TABLE
  } else if (!this._bufferedFiles) {
    // TODO(tec27): deal with the case that the layout is: HT FD BT
    this._state = STATE_STREAMING_DISCARD
  } else if (this._chkBlockEntry) {
    // TODO(tec27): read file from buffered copy immediately
    this._state = STATE_DISCARD_REST
  } else {
    this._error('Invalid SCM file, expected to encounter block table')
  }
}

var BLOCK_TABLE_ENTRY_SIZE = 16
ScmExtractor.prototype._readBlockTable = function() {
  return this._chkBlockIndex >= 0 ? streamBlockTable() : bufferBlockTable()

  function bufferBlockTable() {
    var tableSize = BLOCK_TABLE_ENTRY_SIZE * this._header.blockTableEntries
    if (this._buffer.length < tableSize) return

    this._bufferedBlockEntries = this._buffer.slice(0, tableSize)
    this._consume(tableSize)

    if (this._offset == this._header.hashTableOffset) {
      this._state = STATE_HASH_TABLE
    } else if (!this._bufferedFiles) {
      this._state = STATE_BUFFERING_FILES
    } else {
      return this._error('Invalid SCM, expected to encounter hash table')
    }
  }

  function streamBlockTable() {
    var curEntry = (this._offset - this._header.blockTableOffset) / BLOCK_TABLE_ENTRY_SIZE
    if (curEntry > this._chkBlockIndex) {
      // discard the rest of the table
      var toConsume = (this._header.blockTableEntries - curEntry) * BLOCK_TABLE_ENTRY_SIZE
      if (this._buffer.length < toConsume) return

      this._consume(toConsume)
      if (this._bufferedFiles) {
        // TODO(tec27): pull the chk out of the buffer
        this._state = STATE_DISCARD_REST
      } else {
        this._state = STATE_STREAMING_DISCARD
      }
      return
    }
    if (this._buffer.length < (this._chkBlockIndex - curEntry) * BLOCK_TABLE_ENTRY_SIZE) {
      // not enough data yet, consume all of the complete blocks
      return this._consume(this._buffer.length - (this._buffer.length % 16))
    }

    var entryOffset = (this._chkBlockIndex - curEntry) * BLOCK_TABLE_ENTRY_SIZE
    this._chkBlockEntry = {
      offset: this._buffer.readUInt32LE(entryOffset),
      blockSize: this._buffer.readUInt32LE(entryOffset + 4),
      fileSize: this._buffer.readUInt32LE(entryOffset + 8),
      flags: this._buffer.readUInt32LE(entryOffset + 12)
    }

    var tableLeft = (this._header.blockTableEntries - curEntry) * BLOCK_TABLE_ENTRY_SIZE
    if (tableLeft > this._buffer.length) {
      return this._consume(this._buffer.length)
    }

    this._consume(tableLeft)
    if (this._bufferedFiles) {
      // TODO(tec27): pull the chk out of the buffer
      this._state = STATE_DISCARD_REST
    } else {
      this._state = STATE_STREAMING_DISCARD
    }
  }
}

var HASH_TYPE_TABLE_OFFSET = 0
  , HASH_TYPE_NAME_A = 1
  , HASH_TYPE_NAME_B = 2
  , HASH_TYPE_FILE_KEY = 3
function hashTableOffset(key) {
  return hashString(key, HASH_TYPE_TABLE_OFFSET)
}

function hashNameA(filePath) {
  return hashString(filePath, HASH_TYPE_NAME_A)
}

function hashNameB(filePath) {
  return hashString(filePath, HASH_TYPE_NAME_B)
}

function hashFileKey(key) {
  return hashString(key, HASH_TYPE_FILE_KEY)
}

function hashString(str, hashType) {
  var seed1 = 0x7FED7FED >>> 0
    , seed2 = 0xEEEEEEEE >>> 0
  str = str.toUpperCase()
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i)
    seed1 = (cryptTable[(hashType * 256) + c] ^ (seed1 + seed2)) >>> 0
    seed2 = (c + seed1 + seed2 + (seed2 << 5) + 3) >>> 0
  }

  return seed1
}
