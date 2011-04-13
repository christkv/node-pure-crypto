var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

var OFBMode = exports.OFBMode = function(key, padding, iv, bitblockSize) {
  this.key = key;
  this.iv = iv;
  this.blockSize = bitblockSize == null ? key.getBlockSize() : bitblockSize/8;
  // Ensure iv is same size as block
  if(this.iv.length < this.blockSize) throw "IV must be at least " + this.blockSize + " bytes long";
  // Used when streaming encryption
  this.lastBlock = "";
  this.currentBlock = 0;
}

// Stream the data for encryption
OFBMode.prototype.updateEncrypt = function(src, encoding) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);

  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.encrypt(src));
  } else if(encoding == 'hex') {
    return util.toHex(this.encrypt(src));
  }
  
  throw "encoding not supported " + encoding;
}

OFBMode.prototype.finalEncrypt = function() {  
  return "";
}

OFBMode.prototype.encrypt = function(src) {
  var vector = this.getIV4e();
  var srcLength = src.length;
  var encrypted = this.core(src, vector);

  if(encrypted.length > srcLength) {
    encrypted = encrypted.slice(0, srcLength)
  }
  // Return adjusted binary
  return encrypted;
}

OFBMode.prototype.updateDecrypt = function(src, encoding) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);

  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.decrypt(src));
  } else if(encoding == 'hex') {
    return util.toHex(this.decrypt(src));
  }
  
  throw "encoding not supported " + encoding;
}

OFBMode.prototype.finalDecrypt = function() {
  return "";
}

OFBMode.prototype.decrypt = function(src) {
  var vector = this.getIV4d();
  var srcLength = src.length;
  var decrypted = this.core(src, vector);
  
  if(decrypted.length > srcLength) {
    decrypted = decrypted.slice(0, srcLength);
  }  
  // Return adjusted binary
  return decrypted;
}

OFBMode.prototype.core = function(src, iv) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
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
    this.iv = iv;
  }  
  
  return data;
}

OFBMode.prototype.getIV4e = function() {
  var vec = [];
  if(this.iv) {
    vec = this.iv;
  } else {
    // Generate a iv
    vec = this.prng.nextBytes(vec, this.blockSize);
  }
  return vec;
}

OFBMode.prototype.getIV4d = function() {
	if (this.iv) {
		return this.iv;
	} else {
		throw new Error("an IV must be set before calling decrypt()");
	}
}


