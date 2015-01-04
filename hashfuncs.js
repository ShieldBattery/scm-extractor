var uint = require('cuint').UINT32
  , cryptTable = require('./crypt-table')

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

var _3 = uint(3)
function hashString(str, hashType) {
  var seed1 = uint(0x7FED7FED)
    , seed2 = uint(0xEEEEEEEE)
  str = str.toUpperCase()
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i)
    seed1 = cryptTable[(hashType * 256) + c].clone().xor(seed1.clone().add(seed2))
    seed2.add(seed2.clone().shiftLeft(5)).add(uint(c)).add(seed1).add(_3)
  }

  return seed1.toNumber() >>> 0
}

module.exports = {
  hashTableOffset: hashTableOffset,
  hashNameA: hashNameA,
  hashNameB: hashNameB,
  hashFileKey: hashFileKey
}
