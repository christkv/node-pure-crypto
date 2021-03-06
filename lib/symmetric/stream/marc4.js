var debug = require('sys').debug,
  inspect = require('sys').inspect,
  assert = require('assert'),
  util = require('utils');

var MARC4 = exports.MARC4 = function() {
}

MARC4.prototype.init = function(forEncryption, key, drop) {
  this.forEncryption;
  // Save key
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

// Block size of cipher
MARC4.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
MARC4.prototype.getAlgorithmName = function() { return "MARC4"; }
// Reset cipher
MARC4.prototype.reset = function() {}

// Process a block
MARC4.prototype.processBytes = function(input, inOff, len, out, outOff) {
  inOff = inOff == null ? 0 : inOff;
  outOff = outOff == null ? 0 : outOff;  
  // Marc4
  _marc4(this, input, inOff, out, outOff, this.key, this.drop, this.stream);
  // Set up finished with setup
  this.stream = true;
}

MARC4.prototype.getPoolSize = function() {
  return 256;
}

MARC4.prototype.returnByte = function(input) {
  var data = [input];
  _marc4(this, data, 0, data, 0, this.key, this.drop, this.stream);
  this.stream = true;
  return data[0];
}

var _marc4 = function(self, m, index, out, outOff, k, drop, stream) {
  // Key setup if it's the start of the encryption
  if(stream == null) {
    for (self.i = 0, self.s = []; self.i < 256; self.i++) self.s[self.i] = self.i;
    for (self.i = 0, self.j = 0;  self.i < 256; self.i++) {
    	self.j = (self.j + self.s[self.i] + k[self.i % k.length]) % 256;
    	// Swap
    	self.temp = self.s[self.i];
    	self.s[self.i] = self.s[self.j];
    	self.s[self.j] = self.temp;
    }

    // Clear counters
    self.i = self.j = 0;    
  }

  // Encryption
  for (var k = -drop; k < m.length; k++) {
    self.i = (self.i + 1) % 256;
    self.j = (self.j + self.s[self.i]) % 256;
    // Swap
    self.temp = self.s[self.i];
    self.s[self.i] = self.s[self.j];
    self.s[self.j] = self.temp;
    // Stop here if we're still dropping keystream
    if (k < 0) continue;
    // Encrypt
    out[outOff + k] ^= self.s[(self.s[self.i] + self.s[self.j]) % 256];
  }
}



