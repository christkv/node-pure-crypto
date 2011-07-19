var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// RC5 Implementation in Javascript
const BlockSize = 8;
var ND = 0xFFFFFFFF;

var RC5 = exports.RC5 = function(key, rounds) {
}

RC5.prototype.init = function(forEncryption, key, rounds) {
  this.forEncryption = forEncryption;
  key = key.slice(0);
  
  // Pad the key out if it's less than 128 bits
  for(var i = key.length; i < 16; i++) {
    key.push(0);
  }

  var L = new Array(4);
  // Translate key to integers
  for(var i = 0; i < (key.length / 4); i++) {
    var valueArray = key.slice((i * 4), (i * 4 + 4)).reverse();
    L[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
  
  var T = 0xb7e15163;
  var S = this.S = new Array((2*rounds));
  
  for(var i = 0; i < (2*rounds + 2); i++) {
    S[i] = T;
    T = Long.fromNumber(T).add(Long.fromNumber(0x9e3779b9)).getLowBitsUnsigned();
  }
  
  var A = 0;
  var B = 0;
  var numberOfCalculations = (3 * (S.length > L.length ? S.length : L.length)) - 1;

  // Set up key
  for(var i = 0; i <= numberOfCalculations; i++) {
    var br = Long.fromNumber(S[i % S.length]).add(Long.fromNumber(A)).add(Long.fromNumber(B)).getLowBitsUnsigned();
    S[i % S.length] = A = Long.fromNumber(util.rotl(br, 3)).getLowBitsUnsigned();
    br = Long.fromNumber(L[i % L.length]).add(Long.fromNumber(A)).add(Long.fromNumber(B)).getLowBitsUnsigned();
    L[i % L.length] = B = Long.fromNumber(util.rotl(br, Long.fromNumber(A).add(Long.fromNumber(B)).getLowBitsUnsigned())).getLowBitsUnsigned();
  }  
}


// Block size of cipher
RC5.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
RC5.prototype.getAlgorithmName = function() { return "RC5"; }
// Reset cipher
RC5.prototype.reset = function() {}

// Process a block
RC5.prototype.processBlock = function(input, inOff, inLen) {
  inOff = inOff == null ? 0 : inOff;

  if(this.forEncryption) {
    encryptBlock(this, input, inOff);
  } else {
    decryptBlock(this, input, inOff);
  }
}

var encryptBlock = function(self, input, index) {
  var regs = new Array(2);
  var S = self.S;
  
  for(var i = 0; i < 2; i ++) {
    regs[i] = Long.fromNumber(util.decodeUInt32R(input, index + (i * 4))).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  
  A = Long.fromNumber(A + S[0]).getLowBitsUnsigned();
  B = Long.fromNumber(B + S[1]).getLowBitsUnsigned();

  for(var i = 1; i <= (S.length - 2); i++) {
    A = Long.fromNumber(S[i + 1]).add(Long.fromNumber(util.rotl(A ^ B, B))).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
    B = Long.fromNumber(B^A).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
  }
  
  // Save the encoded bytes
  util.inPlaceEncodeUInt32R(A, input, index + 0);
  util.inPlaceEncodeUInt32R(B, input, index + 4);
}

var decryptBlock = function(self, input, index) {
  var regs = new Array(2);
  var S = self.S;
  
  for(var i = 0; i < 2; i ++) {
    regs[i] = Long.fromNumber(util.decodeUInt32R(input, index + (i * 4))).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  
  A = Long.fromNumber(A).add(S[0]).getLowBitsUnsigned();
  B = Long.fromNumber(B).add(S[1]).getLowBitsUnsigned();

  for(var i = 1; i <= (S.length - 2); i++) {
    var br = Long.fromNumber(B - S[S.length - i]).getLowBitsUnsigned();
    B = Long.fromNumber(A ^ util.rotr(br, A)).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
    B = Long.fromNumber(B^A).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
  }

  A = Long.fromNumber((A - S[0] + MOD) % MOD).getLowBitsUnsigned();
  B = Long.fromNumber((B - S[1] + MOD) % MOD).getLowBitsUnsigned();

  // Save the encoded bytes
  util.inPlaceEncodeUInt32R(A, input, index + 0);
  util.inPlaceEncodeUInt32R(B, input, index + 4);
}

var MOD = 4294967296;



