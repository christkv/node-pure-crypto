var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5,
  BinaryParser = require('binary_parser').BinaryParser;

var copy = function(targetArray, destIndex, sourceArray, sourceIndex, sourceLength) {
  var index = sourceIndex;

  for(var i = destIndex; i < destIndex + sourceLength; i++) {
    targetArray[i] = sourceArray[index++];
  }
}

var toHex = function(array) {
  var s = "";
  for(var i = 0; i < array.length; i++) {
    var v = array[i] != null ? array[i].toString(16) : "0";
    if(v.length == 1) v = "0" + v; 
    s += v.toUpperCase();
  }
  return s;
}

var binaryStringToArray = function(string) {
  var array = [];
  
  for (var i = 0; i < string.length; i++) {
    if (string.charCodeAt(i)<32) {array.push(string.charCodeAt(i));}
    else {array.push(string.charCodeAt(i))}    
  }  
  return array;
}

var arrayToBinaryString = function(array) {
  var string = "";
  
  for(var i = 0; i < array.length; i++) {
    string += BinaryParser.fromByte(array[i]);
  }  
  return string;  
}

// CBC Mode object
var CBCMode = exports.CBCMode = function(aesKey, padding, iv) {
  this.aesKey = aesKey;
  this.iv = iv;
  this.padding = padding;
  this.lastIV = [];
  this.blockSize = aesKey.getBlockSize();
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
  return arrayToBinaryString(this.decrypt(src, true));
}

CBCMode.prototype.finalDecrypt = function() {
  return arrayToBinaryString(this.decrypt(this.lastBytes));;
}

CBCMode.prototype.decrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? binaryStringToArray(src) : src.slice(0);
  var vector = this.getIV4e();
  var tmp = [];
    
  for(var i = 0; i < data.length; i += this.blockSize) {
    copy(tmp, 0, data, i, this.blockSize);
    // Encrypt
    var decrypted = this.aesKey.decrypt(data, i);
    // Copy the decrypted content
    copy(data, i, decrypted, 0, this.blockSize);
    
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];
    }    
    copy(vector, 0, tmp, 0, this.blockSize);
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
    
  return arrayToBinaryString(this.encrypt(src, true));
}

CBCMode.prototype.finalEncrypt = function() {
  return arrayToBinaryString(this.encrypt(this.lastBytes));
}

CBCMode.prototype.encrypt = function(src, nopadding) {
  var data = !Array.isArray(src) ? binaryStringToArray(src) : src.slice(0);
  // Pad the data
  if(nopadding == null) { data = this.padding.pad(data); }
  var vector = this.getIV4e();
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];        
    }

    var encrypted = this.aesKey.encrypt(data, i);
    copy(data, i, encrypted, 0, this.blockSize);
    copy(vector, 0, data, i, this.blockSize)
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

