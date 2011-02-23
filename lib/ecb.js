var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

// ECB Mode object
var ECBMode = exports.ECBMode = function(key, padding, iv) {
  this.key = key;
  this.iv = iv;
  this.padding = padding;
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

ECBMode.prototype.updateDecrypt = function(src) {
  // Pad the source with the last bytes from last update
  if(this.lastBytes != null && this.lastBytes.length > 0) {
    src = this.lastBytes + src;
  }
  // Chop of the last block to ensure we can remove padding if existing
  if(src.length > this.blockSize) {
    this.lastBytes = src.substr(src.length - this.blockSize);
    src = src.substr(0, src.length - this.blockSize);
  }

  return util.arrayToBinaryString(this.decrypt(src, true));
}

ECBMode.prototype.finalDecrypt = function() {
  // Unpack the last packet with padding
  return util.arrayToBinaryString(this.decrypt(this.lastBytes));;
}

ECBMode.prototype.decrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);  
  var tmp = [];
  var dst = [];
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    util.copy(tmp, 0, data, i, this.blockSize);
    tmp = this.key.decrypt(tmp);
    util.copy(dst, i, tmp, 0, this.blockSize);
  }
  
  // Return data unpadded only if we ask it to
  return nopadding == null ? this.padding.unpad(dst) : dst;
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
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var dst = [];
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    var tmp = [];
    util.copy(tmp, 0, data, i, this.blockSize);
    tmp = this.key.encrypt(data, i);
    util.copy(dst, i, tmp, 0, tmp.length);
  }
  return dst;
}



