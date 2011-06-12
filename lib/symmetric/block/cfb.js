var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('prng/pkcs5').PKCS5,
  util = require('utils');

// CBC Mode object
var CFBMode = exports.CFBMode = function(key, padding, iv, bitblockSize) {
  this.key = key;
  this.iv = iv;
  this.blockSize = bitblockSize == null ? key.getBlockSize() : bitblockSize/8;
  // Ensure iv is same size as block
  if(this.iv.length < this.blockSize) throw "IV must be at least " + this.blockSize + " bytes long";
}

CFBMode.prototype.updateDecrypt = function(src, encoding) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);

  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.decrypt(src, true));
  } else if(encoding == 'hex') {
    return util.toHex(this.decrypt(src, true));
  }
  
  throw "encoding not supported " + encoding;
}

CFBMode.prototype.finalDecrypt = function(encoding) {
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString([]);
  } else if(encoding == 'hex') {
    return util.toHex([]);
  }
  
  throw "encoding not supported " + encoding;
}

CFBMode.prototype.decrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var l = data.length;
  var vector = this.getIV4e();
  var tmp = [];
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    vector = this.key.encrypt(vector);
    var chunk = (i + this.blockSize < l) ? this.blockSize : l - i;
    tmp = data.slice(i, i + chunk);
    
    for(var j = 0; j < chunk; j++) {
      data[i + j] ^= vector[j];
    }
    
    vector = tmp.slice(0);
    this.iv = vector;
  }      
  return data;
}

// Stream the data for encryption
CFBMode.prototype.updateEncrypt = function(src, encoding) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);

  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.encrypt(src, true));
  } else if(encoding == 'hex') {
    return util.toHex(this.encrypt(src, true));
  }
  
  throw "encoding not supported " + encoding;
}

CFBMode.prototype.finalEncrypt = function(encoding) {
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString([]);
  } else if(encoding == 'hex') {
    return util.toHex([]);
  }
  
  throw "encoding not supported " + encoding;
}

CFBMode.prototype.encrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var l = data.length;
  var vector = this.getIV4e();
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    vector = this.key.encrypt(vector);
    var chunk = (i + this.blockSize < l) ? this.blockSize : l - i;
    for(var j = 0; j < chunk; j++) {
      data[i + j] ^= vector[j];
    }
    
    vector = data.slice(i, i + chunk);
    this.iv = vector;
  }
  
  return data;
}

CFBMode.prototype.getIV4e = function() {
  var vec = [];
  if(this.iv) {
    vec = this.iv.slice(0);
  } else {
    // Generate a iv
    vec = this.prng.nextBytes(vec, this.blockSize);
  }
  return vec;
}

CFBMode.prototype.getIV4d = function() {
	if (this.iv) {
		return this.iv.slice(0);
	} else {
		throw new Error("an IV must be set before calling decrypt()");
	}
}


