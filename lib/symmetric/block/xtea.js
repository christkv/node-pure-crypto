//  AESKey
//  Derived from:
//    as3crypto http://code.google.com/p/as3crypto/ by Henri Torgemane
//    A public domain implementation from Karl Malbrain, malbrain@yahoo.com
//    (http://www.geocities.com/malbrain/aestable_c.html)
//  See LICENSE.txt for full license information.
var debug = require('sys').debug,
  inspect = require('sys').inspect,
  puts = require('sys').puts,
  assert = require('assert'),
  util = require('utils'),
  chr = String.fromCharCode;  

var delta = 0x9E3779B9;

// Number of encryption runs
var XTea = exports.XTea = function() {
}

XTea.prototype.init = function(forEncryption, key, rounds) {
  this.forEncryption = forEncryption;
  // Unpack the keys
  var index = 0;
  this._S = [0, 0, 0, 0];
  this._sum0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  this._sum1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  this.rounds = rounds == null ? 32 : rounds;
  // Decode the key
  setKey(this, key);
}

var setKey = function(self, key) {
  var i = 0, j = 0;
  
  for(i = j = 0; i < 4; i++, j += 4) {
    self._S[i] = util.decodeUInt32(key, j);
  }
  
  for(i = j = 0; i < self.rounds; i++) {
    self._sum0[i] = (j + self._S[j & 3]);
    j = j + delta;
    self._sum1[i] = (j + self._S[j >>> 11 & 3]);
  }  
}

// Block size of cipher
XTea.prototype.getBlockSize = function() { return 8; }
// Algorithm Name
XTea.prototype.getAlgorithmName = function() { return "XTEA"; }
// Reset cipher
XTea.prototype.reset = function() {}

// Process a block
XTea.prototype.processBlock = function(input, inOff, inLen) {
  if(this.forEncryption) {
    encrypt(this, input, inOff);
  } else {
    decrypt(this, input, inOff);
  }
}

var encrypt = function(self, block, index) {
  if(index == null) index = 0;
  // Read the two integers from the block
  var v0 = util.decodeUInt32(block, index);
  var v1 = util.decodeUInt32(block, index +  4);
  
  // Encrypt
  for (var i = 0; i < self.rounds; i++) {
    v0 += ((v1 << 4 ^ v1 >>> 5) + v1) ^ self._sum0[i];
    v1 += ((v0 << 4 ^ v0 >>> 5) + v0) ^ self._sum1[i];
  }

  // Encode the results in the block
  util.inPlaceEncodeUInt32(v0, block, index);
  util.inPlaceEncodeUInt32(v1, block, index + 4);
}

var decrypt = function(self, block, index) {
  if(index == null) index = 0;
  // Read the two integers from the block
  var v0 = util.decodeUInt32(block, index);
  var v1 = util.decodeUInt32(block, index + 4)

  for(var i = self.rounds-1; i >= 0; i--) {
    v1  -= ((v0 << 4 ^ v0 >>> 5) + v0) ^ self._sum1[i];
    v0  -= ((v1 << 4 ^ v1 >>> 5) + v1) ^ self._sum0[i];
  }
  
  // Encode the results in the block
  util.inPlaceEncodeUInt32(v0, block, index);
  util.inPlaceEncodeUInt32(v1, block, index + 4);
}








