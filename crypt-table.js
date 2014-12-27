var table = new Array(1280)

var seed = 0x00100001
  , index1 = 0
  , index2 = 0
  , i = 0

for (index1 = 0; index1 < 256; index1++) {
  for (index2 = index1, i = 0; i < 5; i++, index2 += 256) {
    seed = ((seed * 125 + 3) >>> 0) % 0x2AAAAB
    var temp1 = (seed & 0xFFFF) << 16

    seed = ((seed * 125 + 3) >>> 0) % 0x2AAAAB
    var temp2 = (seed & 0xFFFF)

    table[index2] = (temp1 | temp2) >>> 0
  }
}

module.exports = table
