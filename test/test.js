var extractor = require('./')
  , fs = require('fs')

fs.createReadStream('lt.scm')
  .pipe(extractor())
  .pipe(fs.createWriteStream('scenario.chk'))
