var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// IDEA Implementation in Javascript
const BlockSize = 8;
var ND = 0xFFFFFFFF;
var USHORT = 0x10000;

var IDEA = exports.IDEA = function(key) {
}

IDEA.prototype.init = function(forEncryption, key) {
  this.forEncryption = forEncryption;
  // Create 16 but values
  var l_key = new Array(KEYLEN);
  
  // Create the 16 bit values
  for(var i = 0; i < key.length / 2; i++) {
    l_key[i] = util.decodeUInt16(key, (i*2));
  }
  
  if(forEncryption) {
    this.key = createEncryptionKey(l_key.slice(0));
  } else {
    this.key = createDecryptionKey(l_key.slice(0));
  }
}

var createDecryptionKey = function(key) {
  var encryptKeys = createEncryptionKey(key);
  var decryptKeys = new Array(52);
  // Create key
  decryptKeys[48] = mulInv(encryptKeys.shift());
  decryptKeys[49] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
  decryptKeys[50] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
  decryptKeys[51] = mulInv(encryptKeys.shift());
  
  for(var i = 42; i >= 0; i -= 6) {
    decryptKeys[i + 4] = Long.fromNumber(encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
    decryptKeys[i + 5] = Long.fromNumber(encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
    decryptKeys[i] = mulInv(encryptKeys.shift());
    
    if(i == 0) {
      decryptKeys[1] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
      decryptKeys[2] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
    } else {
      decryptKeys[i + 2] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
      decryptKeys[i + 1] = Long.fromNumber(-1*encryptKeys.shift()).getLowBitsUnsigned() % USHORT;
    }
    decryptKeys[i + 3] = mulInv(encryptKeys.shift());
  }
  
  return decryptKeys;
}

var mulInv = function(x) {
  var modulus = 0x10001;
  x = Long.fromNumber(x).getLowBitsUnsigned() % USHORT;
  if(x <= 1) return x;
  
  var t1 = Long.fromNumber(USHORT / x).getLowBitsUnsigned();
  var y = modulus % x;

  if(y == 1) {
    var inv = (1 - t1) & 0xffff;
    return inv;
  }
  
  var t0 = 1;
  while(y != 1) {
    var q = Long.fromNumber(x / y).getLowBitsUnsigned();
    x = Long.fromNumber(x % y).getLowBitsUnsigned();
    t0 = Long.fromNumber(t0 + (q * t1)).getLowBitsUnsigned();
    if(x == 1) return t0;
    q = Long.fromNumber(y / x).getLowBitsUnsigned();
    y = Long.fromNumber(y % x).getLowBitsUnsigned();
    t1 = Long.fromNumber(t1 + (q * t0)).getLowBitsUnsigned();
  }
  
  var inv = Long.fromNumber((1 - t1) & 0xffff).getLowBitsUnsigned();
  return inv;
}

var createEncryptionKey = function(key) {
  // Create the key
  for(var i = 8; i < KEYLEN; i++) {
    var a = ((i + 1) % 8 > 0) ? (i-7)  : (i-15);
    var b = ((i + 2) % 8 < 2) ? (i-14) : (i-6);
    key[i] = ((key[a] << 9)| (key[b] >> 7)) % USHORT;
  } 
  return key;  
}

// Block size of cipher
IDEA.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
IDEA.prototype.getAlgorithmName = function() { return "IDEA"; }
// Reset cipher
IDEA.prototype.reset = function() {}

// Process a block
IDEA.prototype.processBlock = function(input, inOff, inLen) {
  inOff = inOff == null ? 0 : inOff;
  cryptPair(input, this.key, inOff);
}

var cryptPair = function(block, key, index) {
  // Prepare the word array
  var word = [util.decodeUInt16(block, index)
    , util.decodeUInt16(block, index + 2)
    , util.decodeUInt16(block, index + 4)
    , util.decodeUInt16(block, index + 6)];
  var k = key.slice(0);
  
  for(var i = 8; i > 0; i--) {
    word[0] = Long.fromNumber(mul(word[0], k.shift())).getLowBitsUnsigned();
    word[1] = Long.fromNumber((word[1] + k.shift()) % USHORT).getLowBitsUnsigned();
    word[2] = Long.fromNumber((word[2] + k.shift()) % USHORT).getLowBitsUnsigned();
    word[3] = Long.fromNumber(mul(word[3], k.shift())).getLowBitsUnsigned();

    var t2 = Long.fromNumber(word[0] ^ word[2]).getLowBitsUnsigned();
    t2 = Long.fromNumber(mul(t2, k.shift())).getLowBitsUnsigned();
    var t1 = Long.fromNumber((t2 + (word[1] ^ word[3])) % USHORT).getLowBitsUnsigned();
    var v = k.shift()
    t1 = Long.fromNumber(mul(t1, v)).getLowBitsUnsigned();
    t2 = Long.fromNumber((t1 + t2) % USHORT).getLowBitsUnsigned();
    
    word[0] = Long.fromNumber(word[0] ^ t1).getLowBitsUnsigned();
    word[3] = Long.fromNumber(word[3] ^ t2).getLowBitsUnsigned();
    t2 = Long.fromNumber(t2 ^ word[1]).getLowBitsUnsigned();
    word[1] = Long.fromNumber(word[2] ^ t1).getLowBitsUnsigned();
    word[2] = t2
  }
  
  var result = [];
  result.push(Long.fromNumber(mul(word[0], k.shift())).getLowBitsUnsigned());
  result.push(word[2] + k.shift() % USHORT);
  result.push(word[1] + k.shift() % USHORT);
  result.push(Long.fromNumber(mul(word[3], k.shift())).getLowBitsUnsigned());

  util.inPlaceEncodeUInt16(result[0], block, index);
  util.inPlaceEncodeUInt16(result[1], block, index + 2);
  util.inPlaceEncodeUInt16(result[2], block, index + 4);
  util.inPlaceEncodeUInt16(result[3], block, index + 6);
  return block;
}

var mul = function(a, b) {
  var modulus = 0x10001;
  if(a == 0) return Long.fromNumber(1).subtract(Long.fromNumber(b)).getLowBitsUnsigned() % USHORT;
  if(b == 0) return Long.fromNumber(1).subtract(Long.fromNumber(a)).getLowBitsUnsigned() % USHORT;
  return Long.fromNumber(a).multiply(Long.fromNumber(b)).getLowBitsUnsigned()% modulus;
}

var KEYS_PER_ROUND = 6;
var ROUNDS = 8;
var KEYLEN = (KEYS_PER_ROUND*ROUNDS + 4);
