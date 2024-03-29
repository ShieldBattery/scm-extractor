"use strict"; // eslint-disable-line quotes,semi

const test = require('tape').test
const fs = require('fs')
const concat = require('concat-stream')
const through = require('through2')

const createExtractor = require('../')

test('extracts Blizzard official maps (LT)', function(t) {
  doTest(t, 'lt.scm', 'lt.scenario.chk')
})

test('extracts a map when buffers are split up', function(t) {
  const e = createExtractor()
  let actual
  let expected

  t.plan(1)
  fs.createReadStream(__dirname + '/lt.scm').pipe(through(function(block, enc, done) {
    // be super-adversarial with reading: every byte in a separate buffer
    for (let i = 0; i < block.length; i++) {
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

test('extracts maps with MPQ data offset from the start', function(t) {
  doTest(t, 'lt-offset-from-start.scm', 'lt.scenario.chk')
})

test('extracts really small maps', function(t) {
  doTest(t, 'smallest.scm', 'smallest.chk')
})

test('extracts maps with imploded blocks', function(t) {
  doTest(t, 'imploded.scm', 'imploded.chk')
})

test('extracts maps with negative offsets', function(t) {
  doTest(t, 'negativeoffsets.scx', 'negativeoffsets.chk')
})

test('extracts protected maps (0)', function(t) {
  doTest(t, 'protected-0.scx', 'protected-0.chk')
})

test('extracts protected maps (1)', function(t) {
  doTest(t, 'protected-1.scm', 'protected-1.chk')
})

test('extracts protected maps (2)', function(t) {
  doTest(t, 'protected-2.scx', 'protected-2.chk')
})

test('extracts protected maps (3)', function(t) {
  doTest(t, 'protected-3.scx', 'protected-3.chk')
})

test('extracts protected maps (4)', function(t) {
  // This map has set the unsectored (0x01000000) block flag to mislead mpq editors.
  // This flag is only supported by Storm versions which are newer than what BW has.
  // Hopefully newer patches won't update Storm to support this flag...
  doTest(t, 'protected-4.scx', 'protected-4.chk')
})

test('extracts protected maps (5)', function(t) {
  doTest(t, 'protected-5.scm', 'protected-5.chk')
})

test('extracts protected maps (6)', function(t) {
  doTest(t, 'protected-6.scx', 'protected-6.chk')
})

test('extracts maps compressed with DEFLATE', function(t) {
  doTest(t, 'deflate.scx', 'deflate.chk')
})

function doTest(t, compressed, uncompressed) {
  const e = createExtractor()
  let actual
  let expected

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
