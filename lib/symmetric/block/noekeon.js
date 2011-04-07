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

var Noekeon = exports.Noekeon = function(key, rounds) {
  this.state = [0, 0, 0, 0]; // a
  this.subKeys = [0, 0, 0, 0]; // k
  this.decryptKeys = [0, 0, 0, 0];

  this.subKeys[0] = util.decodeUInt32(key, 0);
  this.subKeys[1] = util.decodeUInt32(key, 4);
  this.subKeys[2] = util.decodeUInt32(key, 8);
  this.subKeys[3] = util.decodeUInt32(key, 12);
}

Noekeon.prototype.getBlockSize = function() {
  return BlockSize;
}

Noekeon.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptBlock(src.slice(index, index + BlockSize));
}

Noekeon.prototype.encryptBlock = function(input) {
  this.state[0] = util.decodeUInt32(input, 0);
  this.state[1] = util.decodeUInt32(input, 4);
  this.state[2] = util.decodeUInt32(input, 8);
  this.state[3] = util.decodeUInt32(input, 12);

  var i = 0;
  for(i = 0; i < GenericSize; i++) {
    this.state[0] = this.state[0] ^ roundConstants[i];
    theta(this.state, this.subKeys);
    pi1(this.state);
    gamma(this.state);
    pi2(this.state);
  }
  
  this.state[0] = this.state[0] ^ roundConstants[i];
  theta(this.state, this.subKeys);
  
  // Write out data
  util.inPlaceEncodeUInt32(this.state[0], input, 0);
  util.inPlaceEncodeUInt32(this.state[1], input, 4);
  util.inPlaceEncodeUInt32(this.state[2], input, 8);
  util.inPlaceEncodeUInt32(this.state[3], input, 12);  
  return input; 
}

Noekeon.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.decryptBlock(src.slice(index, index + BlockSize));
}

Noekeon.prototype.decryptBlock = function(input) {
  this.state[0] = util.decodeUInt32(input, 0);
  this.state[1] = util.decodeUInt32(input, 4);
  this.state[2] = util.decodeUInt32(input, 8);
  this.state[3] = util.decodeUInt32(input, 12);
  // Copy subkeys
  this.decryptKeys = this.subKeys.slice(0);
  theta(this.decryptKeys, nullVector);

  var i = 0;
  for(i = GenericSize; i > 0; i--) {
    theta(this.state, this.decryptKeys);
    this.state[0] ^= roundConstants[i];
    pi1(this.state);
    gamma(this.state);
    pi2(this.state);    
  }
  
  theta(this.state, this.decryptKeys);
  this.state[0] ^= roundConstants[i];
  
  // Write out data
  util.inPlaceEncodeUInt32(this.state[0], input, 0);
  util.inPlaceEncodeUInt32(this.state[1], input, 4);
  util.inPlaceEncodeUInt32(this.state[2], input, 8);
  util.inPlaceEncodeUInt32(this.state[3], input, 12);
  return input;   
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






