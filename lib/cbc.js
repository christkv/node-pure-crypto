var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

// CBC Mode object
var CBCMode = exports.CBCMode = function(key, padding, iv) {
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

CBCMode.prototype.updateDecrypt = function(src) {
  var numberOfBlocks = src.length / this.blockSize;  
  if(numberOfBlocks > 1) {
    this.lastBytes = src.substr((numberOfBlocks - 1)*this.blockSize);
    src = src.substr(0, src.length - this.blockSize);
  } else {
    this.lastBytes = "";
  }    

  // Decrypt without unpadding
  return util.arrayToBinaryString(this.decrypt(src, true));
}

CBCMode.prototype.finalDecrypt = function() {
  return util.arrayToBinaryString(this.decrypt(this.lastBytes));;
}

CBCMode.prototype.decrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var vector = this.getIV4e();
  var tmp = [];
    
  for(var i = 0; i < data.length; i += this.blockSize) {
    util.copy(tmp, 0, data, i, this.blockSize);
    // Encrypt
    var decrypted = this.key.decrypt(data, i);
    // Copy the decrypted content
    util.copy(data, i, decrypted, 0, this.blockSize);
    
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];
    }    
    util.copy(vector, 0, tmp, 0, this.blockSize);
    this.iv = vector;
  }
  
  // Return data unpadded only if we ask it to
  return nopadding == null ? this.padding.unpad(data) : data;
}

// Stream the data for encryption
CBCMode.prototype.updateEncrypt = function(src) {
  // Left over bytes if any
  var leftOverBytes = src.length % this.blockSize;
  // If we have leftover bytes encrypt up to the blocksize available and save the leftover bytes for the final
  if(leftOverBytes > 0) {
    this.lastBytes = src.substr(src.length - leftOverBytes);
    src = src.substr(0, src.length - leftOverBytes);
  } else {
    this.lastBytes = "";
  }
    
  return util.arrayToBinaryString(this.encrypt(src, true));
}

CBCMode.prototype.finalEncrypt = function() {
  return util.arrayToBinaryString(this.encrypt(this.lastBytes));
}

CBCMode.prototype.encrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var vector = this.getIV4e();
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];        
    }

    var encrypted = this.key.encrypt(data, i);
    util.copy(data, i, encrypted, 0, this.blockSize);
    util.copy(vector, 0, data, i, this.blockSize)
    // Save current iv vector in case we are streaming data
    this.iv = vector;
  }

  return data;
}

CBCMode.prototype.getIV4e = function() {
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

