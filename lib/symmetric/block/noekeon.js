var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// Noekeon Implementation in Javascript
const BlockSize = 16;
const GenericSize = 16;

// Used in decryption
var nullVector = [0, 0, 0, 0];
var roundConstants = [0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4];

var Noekeon = exports.Noekeon = function() {
}

Noekeon.prototype.init = function(forEncryption, key) {
  this.forEncryption = forEncryption;
  this.state = [0, 0, 0, 0]; // a
  this.subKeys = [0, 0, 0, 0]; // k
  this.decryptKeys = [0, 0, 0, 0];

  this.subKeys[0] = util.decodeUInt32(key, 0);
  this.subKeys[1] = util.decodeUInt32(key, 4);
  this.subKeys[2] = util.decodeUInt32(key, 8);
  this.subKeys[3] = util.decodeUInt32(key, 12);  
}


// Block size of cipher
Noekeon.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
Noekeon.prototype.getAlgorithmName = function() { return "NOEKEON"; }
// Reset cipher
Noekeon.prototype.reset = function() {}

// Process a block
Noekeon.prototype.processBlock = function(input, inOff, out, outOff) {
  inOff = inOff == null ? 0 : inOff;
  outOff = outOff == null ? 0 : outOff;

  if(this.forEncryption) {
    return encryptBlock(this, input, inOff, out, outOff);
  } else {
    return decryptBlock(this, input, inOff, out, outOff);
  }
}

var encryptBlock = function(self, input, index, out, outOff) {
  self.state[0] = util.decodeUInt32(input, index + 0);
  self.state[1] = util.decodeUInt32(input, index + 4);
  self.state[2] = util.decodeUInt32(input, index + 8);
  self.state[3] = util.decodeUInt32(input, index + 12);

  var i = 0;
  for(i = 0; i < GenericSize; i++) {
    self.state[0] = self.state[0] ^ roundConstants[i];
    theta(self.state, self.subKeys);
    pi1(self.state);
    gamma(self.state);
    pi2(self.state);
  }
  
  self.state[0] = self.state[0] ^ roundConstants[i];
  theta(self.state, self.subKeys);
  
  // Write out data
  util.inPlaceEncodeUInt32(self.state[0], out, outOff + 0);
  util.inPlaceEncodeUInt32(self.state[1], out, outOff + 4);
  util.inPlaceEncodeUInt32(self.state[2], out, outOff + 8);
  util.inPlaceEncodeUInt32(self.state[3], out, outOff + 12);  
  return BlockSize;
}

var decryptBlock = function(self, input, index, out, outOff) {
  self.state[0] = util.decodeUInt32(input, index + 0);
  self.state[1] = util.decodeUInt32(input, index + 4);
  self.state[2] = util.decodeUInt32(input, index + 8);
  self.state[3] = util.decodeUInt32(input, index + 12);
  // Copy subkeys
  self.decryptKeys = self.subKeys.slice(0);
  theta(self.decryptKeys, nullVector);

  var i = 0;
  for(i = GenericSize; i > 0; i--) {
    theta(self.state, self.decryptKeys);
    self.state[0] ^= roundConstants[i];
    pi1(self.state);
    gamma(self.state);
    pi2(self.state);    
  }
  
  theta(self.state, self.decryptKeys);
  self.state[0] ^= roundConstants[i];
  
  // Write out data
  util.inPlaceEncodeUInt32(self.state[0], out, outOff + 0);
  util.inPlaceEncodeUInt32(self.state[1], out, outOff + 4);
  util.inPlaceEncodeUInt32(self.state[2], out, outOff + 8);
  util.inPlaceEncodeUInt32(self.state[3], out, outOff + 12);
  return BlockSize;
}

var gamma = function(a) {
  a[1] ^= ~a[3] & ~a[2];
  a[0] ^= a[2] & a[1];
  
  var tmp = a[3];
  a[3]  = a[0];
  a[0]  = tmp;
  a[2] ^= a[0]^a[1]^a[3];
  
  a[1] ^= ~a[3] & ~a[2];
  a[0] ^= a[2] & a[1];
}

var theta = function(a, k) {
  var tmp;    
  tmp = a[0]^a[2]; 
  tmp ^= util.rotl(tmp,8) ^ util.rotl(tmp,24); 
  a[1] ^= tmp; 
  a[3] ^= tmp; 
  
  for (var i = 0; i < 4; i++) {
    a[i] ^= k[i];
  }
  
  tmp = a[1]^a[3]; 
  tmp ^= util.rotl(tmp,8) ^ util.rotl(tmp,24); 
  a[0] ^= tmp; 
  a[2] ^= tmp;
}

var pi1 = function(a) {
  a[1] = util.rotl(a[1], 1);
  a[2] = util.rotl(a[2], 5);
  a[3] = util.rotl(a[3], 2);
}

var pi2 = function(a) {
  a[1] = util.rotl(a[1], 31);
  a[2] = util.rotl(a[2], 27);
  a[3] = util.rotl(a[3], 30);
}






