var debug = require('sys').debug,
  inspect = require('sys').inspect;

var PKCS7 = exports.PKCS7 = function(blockSize) {
  this.blockSize = blockSize;
}

PKCS7.prototype.unpad = function(data) {
  var count = data.length % this.blockSize;
  // This is not a padded block as it's a perfect blocksize length
  if(count != 0) throw new Error("PKCS#7::unpad: ByteArray.length isn't a multiple of the blockSize");
  count = data[data.length - 1] & 0xff;
  for(var i = count; i > 0; i--) {
    var value = data[data.length - 1];
    // Weird javascript trick to cut the end of an array
    data.length--;
    if(count != value) throw Error("PKCS#7:unpad: Invalid padding value. expected ["+count+"], found ["+value+"]");
  }  
  return data;
}

PKCS7.prototype.pad = function(data, bufOff) {
  bufOff = bufOff == null ? 0 : bufOff;
  
  var code = data.length - bufOff;
  while(bufOff < data.length) {
    data[bufOff] = code;
    bufOff = bufOff + 1;
  }
  
  return data;
}

PKCS7.prototype.setBlockSize = function(bs) {
  this.blockSize = bs;
}