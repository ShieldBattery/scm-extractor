"use strict"; // eslint-disable-line quotes,semi

const uint = require('cuint').UINT32
const cryptTable = require('./crypt-table')

const HASH_TYPE_TABLE_OFFSET = 0
const HASH_TYPE_NAME_A = 1
const HASH_TYPE_NAME_B = 2
const HASH_TYPE_FILE_KEY = 3
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

const _3 = uint(3)
function hashString(str, hashType) {
  let seed1 = uint(0x7FED7FED)
  const seed2 = uint(0xEEEEEEEE)
  const strUpper = str.toUpperCase()
  for (let i = 0; i < strUpper.length; i++) {
    const c = strUpper.charCodeAt(i)
    seed1 = cryptTable[(hashType * 256) + c].clone().xor(seed1.clone().add(seed2))
    seed2.add(seed2.clone().shiftLeft(5)).add(uint(c)).add(seed1).add(_3)
  }

  return seed1.toNumber() >>> 0
}

module.exports = {
  hashTableOffset,
  hashNameA,
  hashNameB,
  hashFileKey,
}
