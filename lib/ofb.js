var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

var OFBMode = exports.OFBMode = function(key, padding, iv) {
  this.key = key;
  this.iv = iv;
  this.padding = padding;
  this.lastIV = [];
  this.blockSize = key.getBlockSize();

  // Used when streaming encryption
  this.lastBlock = "";
  this.currentBlock = 0;
  
  // Ensure we have proper padding
  if(this.padding == null) {
    this.padding = new PKCS5(this.blockSize);
  } else {
    this.padding.setBlockSize(this.blockSize);
  }  
}

OFBMode.prototype.encrypt = function(src) {
  var vector = this.getIV4d();
  return this.core(src, vector);
}

OFBMode.prototype.core = function(src, iv) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var length = data.length;
  var tmp = [];
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    iv = this.key.encrypt(iv);
    util.copy(tmp, 0, iv, 0, this.blockSize);
    var chunk = (i * this.blockSize < length) ? this.blockSize : length - i;

    for(var j = 0; j < chunk; j++) {
      data[i+j] ^= iv[j];
    }
    util.copy(iv, 0, tmp, 0, this.blockSize);
  }  
  return data;
}

OFBMode.prototype.getIV4d = function() {
	if (this.iv) {
		return this.iv.slice(0);
	} else {
		throw new Error("an IV must be set before calling decrypt()");
	}
}


