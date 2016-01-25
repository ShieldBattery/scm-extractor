"use strict"; // eslint-disable-line quotes,semi

const uint = require('cuint').UINT32

const table = new Array(1280)

let seed = uint(0x00100001)
let index1 = 0
let index2 = 0
let i = 0

const _125 = uint(125)
const _3 = uint(3)
const _FFFF = uint(0xFFFF)

for (index1 = 0; index1 < 256; index1++) {
  for (index2 = index1, i = 0; i < 5; i++, index2 += 256) {
    seed = uint(seed.multiply(_125).add(_3).toNumber() % 0x2AAAAB)
    const temp1 = seed.clone().and(_FFFF).shiftLeft(16)

    seed = uint(seed.multiply(_125).add(_3).toNumber() % 0x2AAAAB)
    const temp2 = seed.clone().and(_FFFF)

    table[index2] = temp1.or(temp2)
  }
}

module.exports = table
