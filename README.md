# scm-extractor

A pure JS library to extract the underlying CHK file from StarCraft 1 scenarios files.

[![Build Status](https://img.shields.io/travis/tec27/scm-extractor.svg?style=flat)](https://travis-ci.org/tec27/scm-extractor)
[![NPM](https://img.shields.io/npm/v/scm-extractor.svg?style=flat)](https://www.npmjs.org/package/scm-extractor)

[![NPM](https://nodei.co/npm/scm-extractor.png)](https://nodei.co/npm/scm-extractor/)

## Usage

**scm-extractor** is a node.js `Transform` stream. To use it, simply pipe SCM/SCX data into it, and pipe the output (CHK file data) somewhere useful.

### Example

```javascript
import fs from 'fs'
import concat from 'concat-stream'
import createExtractor from 'scm-extractor'

fs.createReadStream(__dirname + '/Lost Temple.scm')
  .pipe(createExtractor())
  .pipe(concat(data => {
    // do something with the CHK data here...
  }))
```

## See also

For a pure JS CHK parsing solution, see [bw-chk](https://github.com/neivv/bw-chk).

## License
MIT
