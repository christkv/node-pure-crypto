var debug = require('sys').debug,
  inspect = require('sys').inspect;

var PKCS5 = exports.PKCS5 = function(blockSize) {
  this.blockSize = blockSize;
}

PKCS5.prototype.unpad = function(data) {
  var count = data.length % this.blockSize;
  // This is not a padded block as it's a perfect blocksize length
  if(count != 0) throw new Error("PKCS#5::unpad: ByteArray.length isn't a multiple of the blockSize");
  count = data[data.length - 1];
  for(var i = count; i > 0; i--) {
    var value = data[data.length - 1];
    // Weird javascript trick to cut the end of an array
    data.length--;
    if(count != value) throw Error("PKCS#5:unpad: Invalid padding value. expected ["+count+"], found ["+value+"]");
  }  
  return data;
}

PKCS5.prototype.pad = function(data) {
  // Calculate needed padding
  var count = this.blockSize - data.length % this.blockSize;
  for(var i = 0; i < count; i++) {
    data[data.length] = count;
  }
  return data;
}

PKCS5.prototype.setBlockSize = function(bs) {
  this.blockSize = bs;
}