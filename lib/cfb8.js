var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  util = require('utils');

// CBC Mode object
var CFB8Mode = exports.CFB8Mode = function(key, padding, iv) {
  this.key = key;
  this.iv = iv;
  this.blockSize = key.getBlockSize();
  // // Used when streaming encryption
  // this.lastBlock = "";
  // this.currentBlock = 0;
  
}

CFB8Mode.prototype.updateDecrypt = function(src) {
  // var numberOfBlocks = src.length / this.blockSize;  
  // if(numberOfBlocks > 1) {
  //   this.lastBytes = src.substr((numberOfBlocks - 1)*this.blockSize);
  //   src = src.substr(0, src.length - this.blockSize);
  // } else {
  //   this.lastBytes = "";
  // }    
  // 
  // // Decrypt without unpadding
  // return util.arrayToBinaryString(this.decrypt(src, true));
}

CFB8Mode.prototype.finalDecrypt = function() {
  // return util.arrayToBinaryString(this.decrypt(this.lastBytes));;
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
  }  
  return data;
}

// Stream the data for encryption
CFB8Mode.prototype.updateEncrypt = function(src) {
  // // Left over bytes if any
  // var leftOverBytes = src.length % this.blockSize;
  // // If we have leftover bytes encrypt up to the blocksize available and save the leftover bytes for the final
  // if(leftOverBytes > 0) {
  //   this.lastBytes = src.substr(src.length - leftOverBytes);
  //   src = src.substr(0, src.length - leftOverBytes);
  // } else {
  //   this.lastBytes = "";
  // }
  //   
  // return util.arrayToBinaryString(this.encrypt(src, true));
}

CFB8Mode.prototype.finalEncrypt = function() {
  // return util.arrayToBinaryString(this.encrypt(this.lastBytes));
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

