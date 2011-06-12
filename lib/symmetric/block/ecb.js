var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('prng/pkcs5').PKCS5,
  util = require('utils');

// ECB Mode object
var ECBMode = exports.ECBMode = function(key, padding, iv, bitblockSize) {
  this.key = key;
  this.iv = iv;
  this.padding = padding;
  this.blockSize = bitblockSize == null ? key.getBlockSize() : bitblockSize/8;
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

ECBMode.prototype.updateDecrypt = function(src) {
  // Pad the source with the last bytes from last update
  if(this.lastBytes != null && this.lastBytes.length > 0) {
    src = this.lastBytes + src;
  }
  
  // Chop of the last block to ensure we can remove padding if existing
  if(src.length > this.blockSize) {
    this.lastBytes = src.substr(src.length - this.blockSize);
    src = src.substr(0, src.length - this.blockSize);
    return util.arrayToBinaryString(this.decrypt(src, true));
  } else {
    // Less than the blocksize pad it
    return util.arrayToBinaryString(this.decrypt(src));    
  }
}

// Unpack the last packet with padding
ECBMode.prototype.finalDecrypt = function() {
  return util.arrayToBinaryString(this.decrypt(this.lastBytes));;    
}

ECBMode.prototype.decrypt = function(src, nopadding) {
  if(src == null) return "";
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;  
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    this.key.decrypt(data, i);
  }
  
  // Return data unpadded only if we ask it to
  return nopadding == null ? this.padding.unpad(data) : data;
}

// Stream the data for encryption
ECBMode.prototype.updateEncrypt = function(src) {
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

ECBMode.prototype.finalEncrypt = function() {
  return util.arrayToBinaryString(this.encrypt(this.lastBytes));
}

ECBMode.prototype.encrypt = function(src, nopadding) {
  if(src == null) return "";
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var dst = [];
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    this.key.encrypt(data, i);
  }
  return data;
}



