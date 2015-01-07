var test = require('tape').test
  , fs = require('fs')
  , concat = require('concat-stream')
  , through = require('through2')

var createExtractor = require('../')

test('extracts Blizzard official maps (LT)', function(t) {
  doTest(t, 'lt.scm', 'lt.scenario.chk')
})

test('extracts a map when buffers are split up', function(t) {
  var e = createExtractor()
    , actual
    , expected

  t.plan(1)
  fs.createReadStream(__dirname + '/lt.scm').pipe(through(function(block, enc, done) {
    // be super-adversarial with reading: every byte in a separate buffer
    for (var i = 0; i < block.length; i++) {
      this.push(block.slice(i, i + 1))
    }
    done()
  })).pipe(e).pipe(concat(function(data) {
    actual = data
    checkEq(t, actual, expected)
  })).on('error', function(err) {
    t.fail('extracting error: ' + err)
  })

  fs.createReadStream(__dirname + '/lt.scenario.chk').pipe(concat(function(data) {
    expected = data
    checkEq(t, actual, expected)
  }))
})

function doTest(t, compressed, uncompressed) {
  var e = createExtractor()
    , actual
    , expected

  t.plan(1)

  fs.createReadStream(__dirname + '/' + compressed).pipe(e).pipe(concat(function(data) {
    actual = data
    checkEq(t, actual, expected)
  })).on('error', function(err) {
    t.fail('extracting error: ' + err)
  })
  fs.createReadStream(__dirname + '/' + uncompressed).pipe(concat(function(data) {
    expected = data
    checkEq(t, actual, expected)
  }))
}

function checkEq(t, actual, expected) {
  if (!actual || !expected) {
    return
  }

  t.deepEqual(actual, expected)
}
