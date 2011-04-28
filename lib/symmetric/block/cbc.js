var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

var zeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

// CBC Mode object
var CBCMode = exports.CBCMode = function(key, padding, iv, bitblockSize) {
  this.key = key;
  this.padding = padding;
  this.blockSize = bitblockSize == null ? key.getBlockSize() : bitblockSize/8;  
  this.iv = iv != null ? iv.slice(0) : zeroedArray(this.blockSize);
  this.originalIv = this.iv.slice(0);
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

CBCMode.prototype.getBlockSize = function() {
  return this.key.getBlockSize();
}


CBCMode.prototype.processBlock = function(encrypting, src, srcIndex, dest, destIndex, len) {
  if(encrypting) {
    return this.encrypt(src, true, srcIndex, dest, destIndex, len);
  } else {
    return this.decrypt(src, true, srcIndex, dest, destIndex, len);
  }
} 

CBCMode.prototype.decrypt = function(src, nopadding, srcIndex, dest, destIndex, len) {
  if(src == null) return "";
  if(srcIndex == null) srcIndex = 0;  
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  // Get iv
  var vector = this.getIV4e();
  var tmp = [];  
  
  // If we specify no destination array use the source ones
  if(dest == null) {
    dest = data; 
    destIndex = srcIndex;
    len = data.length;
  }  
  
  for(var i = srcIndex, ii = destIndex; ii < len; i += this.blockSize, ii += this.blockSize) {
    tmp = data.slice(i, i + this.blockSize);
    // Encrypt
    this.key.decrypt(dest, ii);
    
    for(var j = 0; j < this.blockSize; j++) {
      dest[ii + j] = data[i + j] ^ vector[j];
    }    
    vector = tmp;
    this.iv = vector;
  }
  // Return data unpadded only if we ask it to
  return nopadding == null ? this.padding.unpad(dest) : dest;
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

CBCMode.prototype.finalEncrypt = function(encoding) {
  if(encoding == null || encoding == 'binary') {
    return util.arrayToBinaryString(this.encrypt(this.lastBytes));
  } else if(encoding == 'hex') {
    return util.toHex(this.encrypt(this.lastBytes));
  }
  
  throw "encoding not supported " + encoding;
}

CBCMode.prototype.encrypt = function(src, nopadding, srcIndex, dest, destIndex, len) {
  if(src == null) return "";
  if(srcIndex == null) srcIndex = 0;  
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var vector = this.getIV4e();
  
  // If we specify no destination array use the source ones
  if(dest == null) {
    dest = data; 
    destIndex = srcIndex;
    len = data.length;
  }
  
  for(var i = srcIndex, ii = destIndex; ii < len; i += this.blockSize, ii += this.blockSize) {
    for(var j = 0; j < this.blockSize; j++) {
      dest[ii + j] = data[i + j] ^ vector[j];        
    }
    
    var e = this.key.encrypt(dest, ii);
    vector = dest.slice(ii, ii + this.blockSize);
    // Save current iv vector in case we are streaming data
    this.iv = vector;
  }
  
  return dest;
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

CBCMode.prototype.reset = function() {
  this.iv = this.originalIv.slice(0);
  this.key.reset();
}


