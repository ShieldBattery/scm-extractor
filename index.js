var BufferList = require('bl')
  , Transform = require('stream').Transform
  , inherits = require('util').inherits

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
        case STATE_HASH_TABLE:
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
