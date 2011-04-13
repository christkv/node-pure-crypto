var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

// CBC Mode object
var CBCMode = exports.CBCMode = function(key, padding, iv, bitblockSize) {
  this.key = key;
  this.iv = iv.slice(0);
  this.padding = padding;
  this.blockSize = bitblockSize == null ? key.getBlockSize() : bitblockSize/8;
  // Ensure iv is same size as block
  if(this.iv.length < this.blockSize) throw "IV must be at least " + this.blockSize + " bytes long";
  // Used when streaming encryption
  this.lastBlock = [];
  this.currentBlock = 0;
  
  // Ensure we have proper padding
  if(this.padding == null) {
    this.padding = new PKCS5(this.blockSize);
  } else {
    this.padding.setBlockSize(this.blockSize);
  }
}

CBCMode.prototype.updateDecrypt = function(src, encoding) {
  if(src.length < this.blockSize) throw "Encrypted data must be at least " + this.blockSize + " bytes long";  
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  
  // Existing data
  var data = this.lastBytes != null ? this.lastBytes : [];
  // Decrypt the src
  var decrypted = this.decrypt(src, true);
  // Save the last block
  this.lastBytes = decrypted.slice(decrypted.length - this.blockSize);
  decrypted = decrypted.slice(0, decrypted.length - this.blockSize);
  
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(data.concat(decrypted));
  } else if(encoding == 'hex') {
    return util.toHex(data.concat(decrypted));
  }

  throw "encoding not supported " + encoding;
}

CBCMode.prototype.finalDecrypt = function(encoding) {
  var data = [];  
  if(this.lastBytes != null && this.lastBytes.length > 0) {
    data = this.padding.unpad(this.lastBytes);
  }
  
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(data);
  } else if(encoding == 'hex') {
    return util.toHex(data);
  }
  
  throw "encoding not supported " + encoding;
}

CBCMode.prototype.decrypt = function(src, nopadding) {
  if(src == null) return "";
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  var vector = this.getIV4e();
  var tmp = [];
    
  for(var i = 0; i < data.length; i += this.blockSize) {
    tmp = data.slice(i, i + this.blockSize);
    // Encrypt
    this.key.decrypt(data, i);
    
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];
    }    
    vector = tmp;
    // vector = data.    
    this.iv = vector;
  }
  // Return data unpadded only if we ask it to
  return nopadding == null ? this.padding.unpad(data) : data;
}

// Stream the data for encryption
CBCMode.prototype.updateEncrypt = function(src, encoding) {
  // Left over bytes if any
  var leftOverBytes = src.length % this.blockSize;
  // If we have leftover bytes encrypt up to the blocksize available and save the leftover bytes for the final
  if(leftOverBytes > 0) {
    this.lastBytes = src.substr(src.length - leftOverBytes);
    src = src.substr(0, src.length - leftOverBytes);
  } else {
    this.lastBytes = "";
  }
  
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.encrypt(src, true));
  } else if(encoding == 'hex') {
    return util.toHex(this.encrypt(src, true));
  }

  throw "encoding not supported " + encoding;
}

CBCMode.prototype.finalEncrypt = function(binary) {
  return binary != null && binary ? this.encrypt(this.lastBytes) : util.arrayToBinaryString(this.encrypt(this.lastBytes));
}

CBCMode.prototype.encrypt = function(src, nopadding) {
  if(src == null) return "";
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var vector = this.getIV4e();
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];        
    }
    
    var e = this.key.encrypt(data, i);
    // util.copy(vector, 0, data, i, this.blockSize)
    vector = data.slice(i, i + this.blockSize);
    // Save current iv vector in case we are streaming data
    this.iv = vector;
  }

  return data;
}

CBCMode.prototype.getIV4e = function() {
  var vec = [];
  if(this.iv) {
    vec = this.iv;
  } else {
    // Generate a iv
    vec = this.prng.nextBytes(vec, this.blockSize);
  }
  return vec;
}

