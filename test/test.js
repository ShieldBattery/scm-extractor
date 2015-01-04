var extractor = require('../')
  , fs = require('fs')

fs.createReadStream(__dirname + '/lt.scm')
  .pipe(extractor())
  .pipe(fs.createWriteStream(__dirname + '/scenario.chk'))
