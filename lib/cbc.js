var debug = require('sys').debug,
  inspect = require('sys').inspect,
  PKCS5 = require('pkcs5').PKCS5;

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

// CBC Mode object
var CBCMode = exports.CBCMode = function(aesKey, padding, iv) {
  this.aesKey = aesKey;
  this.iv = iv;
  this.padding = padding;
  this.lastIV = [];
  this.blockSize = aesKey.getBlockSize();
  
  // Ensure we have proper padding
  if(this.padding == null) {
    this.padding = new PKCS5(this.blockSize);
  } else {
    this.padding.setBlockSize(this.blockSize);
  }
}

CBCMode.prototype.decrypt = function(src) {
  var data = src.slice(0);
  var vector = this.getIV4e();
  var tmp = [];
    
  for(var i = 0; i < data.length; i += this.blockSize) {
    copy(tmp, 0, src, i, this.blockSize);
    // debug("DE:: ---------------------------------------------------------------------------- 1")
    // debug(toHex(tmp))
    // Encrypt
    var decrypted = this.aesKey.decrypt(data, i);
    // debug("CBCMode ---------------------------------------------------------------------------- 2")
    // debug(toHex(decrypted))
    // Copy the decrypted content
    copy(data, i, decrypted, 0, this.blockSize);
    // debug("DE:: ---------------------------------------------------------------------------- 2")
    // debug(toHex(data))
    
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];
    }
    
    // debug("DE:: ---------------------------------------------------------------------------- 3")
    // debug(toHex(data))
    copy(vector, 0, tmp, 0, this.blockSize);
    // debug("DE:: ---------------------------------------------------------------------------- 4")
    // debug(toHex(vector))
  }

  return this.padding.unpad(data);
}

CBCMode.prototype.encrypt = function(src) {
  var data = src.slice(0);
  // Pad the data
  data = this.padding.pad(data);
  var vector = this.getIV4e();
  // debug("CBCMode ---------------------------------------------------------------------------- 1")
  // debug(toHex(vector))
  
  for(var i = 0; i < data.length; i += this.blockSize) {
    for(var j = 0; j < this.blockSize; j++) {
      data[i+j] ^= vector[j];
    }
    // debug("CBCMode ---------------------------------------------------------------------------- 2")
    // debug(toHex(data))
    
    var encrypted = this.aesKey.encrypt(data, i);
    copy(data, i, encrypted, 0, this.blockSize);
    // debug("CBCMode ---------------------------------------------------------------------------- 3")
    // debug(toHex(data))
    copy(vector, 0, data, i, this.blockSize)
    // debug("CBCMode ---------------------------------------------------------------------------- 4")
    // debug(toHex(vector))
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

// protected function getIV4e():ByteArray {
//  var vec:ByteArray = new ByteArray;
//  if (iv) {
//    vec.writeBytes(iv);
//  } else {
//    prng.nextBytes(vec, blockSize);
//  }
//  lastIV.length=0;
//  lastIV.writeBytes(vec);
//  return vec;
// }
