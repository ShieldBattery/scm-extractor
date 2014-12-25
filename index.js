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
  , STATE_DISCARDING = 5
  , STATE_CHK = 6

inherits(ScmExtractor, Transform)
function ScmExtractor() {
  Transform.call(this)
  this._state = STATE_MAGIC
  this._buffer = new BufferList()

  this._headerSize = -1
  this._archiveSize = -1
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
          break
        case STATE_DISCARDING:
          break
        case STATE_CHK:
          break
      }
    }

    done()
  }

  this._buffer.append(data)
  process()
}

var MAGIC = 'MPQ\x1A'
ScmExtractor.prototype._readMagic = function() {
  if (this._buffer.length < 4) return

  if (this._buffer.toString('ascii', 0, 4) != MAGIC) {
    return this.emit('error', new Error('Invalid SCM header'))
  }

  this._buffer.consume(4)
  this._state = STATE_HEADER_SIZE
}

ScmExtractor.prototype._readHeaderSize = function() {
  if (this._buffer.length < 4) return

  this._headerSize = this._buffer.readUInt32LE(0)
  this._buffer.consume(4)

  if (this._headerSize < 32) {
    return this.emit('error', new Error('Invalid header size'))
  }

  this._state = STATE_ARCHIVE_SIZE
}

ScmExtractor.prototype._readArchiveSize = function() {
  if (this._buffer.length < 4) return

  this._archiveSize = this._buffer.readUInt32LE(0)
  this._buffer.consume(4)

  if (this._archiveSize < this._headerSize) {
    return this.emit('error', new Error('Invalid header/archive size'))
  }

  this._state = STATE_HEADER_CONTENTS
}


