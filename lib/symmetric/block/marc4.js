var debug = require('sys').debug,
  inspect = require('sys').inspect,
  assert = require('assert'),
  util = require('utils');

var MARC4 = exports.MARC4 = function(key, drop) {
  this.key = key;
  // Drop id
  this.drop = drop != null ? drop : 1536;
  // State variables
  this.i = 0;
  this.j = 0;
  this.s = [];
  this.temp = [];
  this.stream = null;
}

MARC4.prototype.encrypt = function(block, index) {
  if(index == null) index = 0;
  return this._marc4(block, this.key, this.drop);
}

MARC4.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  if(this.stream == null) {
    this.stream = true;
    return util.arrayToBinaryString(this._marc4(data, this.key, this.drop));
  } else {
    return util.arrayToBinaryString(this._marc4(data, this.key, 0, this.stream));    
  }
}

MARC4.prototype.finalEncrypt = function() {
  return "";  
}

MARC4.prototype.decrypt = function(block, index) {
  if(index == null) index = 0;
  return this._marc4(block, this.key, this.drop);
}

MARC4.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  if(this.stream == null) {
    this.stream = true;
    return util.arrayToBinaryString(this._marc4(data, this.key, this.drop));
  } else {
    return util.arrayToBinaryString(this._marc4(data, this.key, 0, this.stream));    
  }
}

MARC4.prototype.finalDecrypt = function() {
  return "";  
}

MARC4.prototype._marc4 = function(m, k, drop, stream) {
  // Key setup if it's the start of the encryption
  if(stream == null) {
    for (this.i = 0, this.s = []; this.i < 256; this.i++) this.s[this.i] = this.i;
    for (this.i = 0, this.j = 0;  this.i < 256; this.i++) {
    	this.j = (this.j + this.s[this.i] + k[this.i % k.length]) % 256;
    	// Swap
    	this.temp = this.s[this.i];
    	this.s[this.i] = this.s[this.j];
    	this.s[this.j] = this.temp;
    }

    // Clear counters
    this.i = this.j = 0;    
  }

  // Encryption
  for (var k = -drop; k < m.length; k++) {
    this.i = (this.i + 1) % 256;
    this.j = (this.j + this.s[this.i]) % 256;
    // Swap
    this.temp = this.s[this.i];
    this.s[this.i] = this.s[this.j];
    this.s[this.j] = this.temp;
    // Stop here if we're still dropping keystream
    if (k < 0) continue;
    // Encrypt
    m[k] ^= this.s[(this.s[this.i] + this.s[this.j]) % 256];
  }
  
  return m;  
}



