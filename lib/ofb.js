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

// Stream the data for encryption
OFBMode.prototype.updateEncrypt = function(src) {
  // Left over bytes if any
  var leftOverBytes = src.length % this.blockSize;  
  // If we have leftover bytes encrypt up to the blocksize available and save the leftover bytes for the final
  if(leftOverBytes > 0) {
    this.lastBytes = src.substr(src.length - leftOverBytes);
    src = src.substr(0, src.length - leftOverBytes);
  } else {
    this.lastBytes = "";
  }
    
  return util.arrayToBinaryString(this.encrypt(src));
}

OFBMode.prototype.finalEncrypt = function() {  
  return util.arrayToBinaryString(this.encrypt(this.lastBytes));;
}

OFBMode.prototype.encrypt = function(src) {
  var vector = this.getIV4e();
  var encrypted = this.core(src, vector);

  if(encrypted.length > src.length) {
    encrypted = encrypted.slice(0, src.length)
  }
  // Return adjusted binary
  return encrypted;
}

OFBMode.prototype.updateDecrypt = function(src) {
  // Left over bytes if any
  var leftOverBytes = src.length % this.blockSize;  
  // If we have leftover bytes encrypt up to the blocksize available and save the leftover bytes for the final
  if(leftOverBytes > 0) {
    this.lastBytes = src.substr(src.length - leftOverBytes);
    src = src.substr(0, src.length - leftOverBytes);
  } else {
    this.lastBytes = "";
  }
  // Decrypt
  return util.arrayToBinaryString(this.decrypt(src));
}

OFBMode.prototype.finalDecrypt = function() {
  return util.arrayToBinaryString(this.decrypt(this.lastBytes));;
}

OFBMode.prototype.decrypt = function(src) {
  var vector = this.getIV4d();
  var decrypted = this.core(src, vector);
  
  if(decrypted.length > src.length) {
    decrypted = decrypted.slice(0, src.length)
  }  
  // Return adjusted binary
  return decrypted;
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
    this.iv = iv;
  }  
  
  return data;
}

OFBMode.prototype.getIV4e = function() {
  var vec = [];
  if(this.iv) {
    vec = this.iv.slice(0);
  } else {
    // Generate a iv
    vec = this.prng.nextBytes(vec, this.blockSize);
  }
  // Save last Iv used
  this.lastIV = vec.slice(0);
  return vec;
}

OFBMode.prototype.getIV4d = function() {
	if (this.iv) {
		return this.iv.slice(0);
	} else {
		throw new Error("an IV must be set before calling decrypt()");
	}
}


