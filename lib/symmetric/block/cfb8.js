var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

// CBC Mode object
var CFB8Mode = exports.CFB8Mode = function(key, padding, iv) {
  this.key = key;
  this.iv = iv;
  this.blockSize = key.getBlockSize();
}

CFB8Mode.prototype.updateDecrypt = function(src) {
  return util.arrayToBinaryString(this.decrypt(src, true));
}

CFB8Mode.prototype.finalDecrypt = function() {
  return "";
}

CFB8Mode.prototype.decrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var vector = this.getIV4e();
  var tmp = [];
  
  for(var i = 0; i < data.length; i++) {
    var ch = data[i];
    tmp = vector.slice(0);              // I <- tmp
    vector = this.key.encrypt(vector);  // 0 <- vector
    data[i] ^= vector[0];
    // rotate
    for(var j = 0; j < this.blockSize - 1; j++) {
      vector[j] = tmp[j + 1];
    }
    vector[this.blockSize - 1] = ch;
    this.iv = vector;
  }    
  return data;
}

// Stream the data for encryption
CFB8Mode.prototype.updateEncrypt = function(src) {
  return util.arrayToBinaryString(this.encrypt(src, true));
}

CFB8Mode.prototype.finalEncrypt = function() {
  return "";
}

CFB8Mode.prototype.encrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src.slice(0);
  var vector = this.getIV4e();
  var tmp = [];
  
  for(var i = 0; i < data.length; i++) {
    tmp = vector.slice(0);
    // Encrypt vector
    vector = this.key.encrypt(vector);    
    data[i] ^= vector[0];
    // rotate
    for(var j = 0; j < this.blockSize - 1; j++) {
      vector[j] = tmp[j + 1];
    }
    vector[this.blockSize - 1] = data[i];
    this.iv = vector;
  }
  
  return data;
}

CFB8Mode.prototype.getIV4e = function() {
  var vec = [];
  if(this.iv) {
    vec = this.iv.slice(0);
  } else {
    // Generate a iv
    vec = this.prng.nextBytes(vec, this.blockSize);
  }
  return vec;
}
