var uint = require('cuint').UINT32

var table = new Array(1280)

var seed = uint(0x00100001)
  , index1 = 0
  , index2 = 0
  , i = 0

var _125 = uint(125)
  , _3 = uint(3)
  , _FFFF = uint(0xFFFF)

for (index1 = 0; index1 < 256; index1++) {
  for (index2 = index1, i = 0; i < 5; i++, index2 += 256) {
    seed = uint(seed.multiply(_125).add(_3).toNumber() % 0x2AAAAB)
    var temp1 = seed.clone().and(_FFFF).shiftLeft(16)

    seed = uint(seed.multiply(_125).add(_3).toNumber() % 0x2AAAAB)
    var temp2 = seed.clone().and(_FFFF)

    table[index2] = temp1.or(temp2)
  }
}

module.exports = table
