var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// Serpent Cipher
const BlockSize = 16;

var Serpent = exports.Serpent = function() {
}

Serpent.prototype.init = function(forEncryption, key, rounds) {
  this.forEncryption = forEncryption;
  this.key = keySchedule(key, rounds);  
}

var keySchedule = function(key, rounds) {
  key = key.slice(0);
  // Set default number of rounds to 32
  rounds = rounds == null ? 32 : rounds;
  // key = key.reverse()
  var k0 = [0, 0, 0, 0, 0, 0, 0, 0];
  var k = new Array(32);
  // Length of the key
  var keyLength = key.length;

  // Missing bytes
  var missingBytes = 4 - key.length % 4;  
  for(var i = 0; i < missingBytes; i++) key.push(0);
  var numberOfWords = parseInt(key.length/4);  
  
  for(var i = 0; i < numberOfWords; i++) {
    k0[i] = Long.fromNumber(util.decodeUInt32(key.slice((i*4), (i*4 + 4)).reverse(), 0)).getLowBitsUnsigned();
  }
  
  if(keyLength < 32) {
    k0[parseInt(keyLength/4)] = k0[parseInt(keyLength/4)] | (1 << ((keyLength % 4) * 8));
  }
  
  var t = k0[7];
  // Let's modify the key
  for(var i = 0; i < 8; ++i) {
    k[i] = k0[i] = t = Long.fromNumber(util.rotl(k0[i] ^ k0[(i + 3)%8] ^ k0[(i + 5)%8] ^ t ^ 0x9e3779b9 ^ i, 11)).getLowBitsUnsigned();
  }
  
  for(var i = 8; i < 4*(rounds+1); ++i) {
    var r = Long.fromNumber(k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ t ^ 0x9e3779b9 ^ i).getLowBitsUnsigned();
    k[i] = t = Long.fromNumber(util.rotl(r, 11)).getLowBitsUnsigned();
  }
  
  // slide the key 20 spaces to the right
  k = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].concat(k);
  // index in k
  var index = 0;
  // Declare some place holders
  var values = [k, [0, 0, 0, 0, 0]];
  for(var i = 0; i < rounds/8; i++) {
    values = afterS2(values, index, LK);
    values = afterS2(values, index, S3);
    values = afterS3(values, index, SK);
    values = afterS1(values, index, LK);
    values = afterS1(values, index, S2);
    values = afterS2(values, index, SK);
    values = afterS0(values, index, LK);
    values = afterS0(values, index, S1);
    values = afterS1(values, index, SK);
    values = beforeS0(values, index, LK);
    values = beforeS0(values, index, S0);
    values = afterS0(values, index, SK);
    
    // Adjust the index
    index = index + (8*4);
    
    values = afterS6(values, index, LK);
    values = afterS6(values, index, S7);
    values = afterS7(values, index, SK);
    values = afterS5(values, index, LK);
    values = afterS5(values, index, S6);
    values = afterS6(values, index, SK);
    values = afterS4(values, index, LK);
    values = afterS4(values, index, S5);
    values = afterS5(values, index, SK);
    values = afterS3(values, index, LK);
    values = afterS3(values, index, S4);
    values = afterS4(values, index, SK);
  }
  
  values = afterS2(values, index, LK);
  values = afterS2(values, index, S3);
  values = afterS3(values, index, SK);
  return k.slice(20)  
}

// Block size of cipher
Serpent.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
Serpent.prototype.getAlgorithmName = function() { return "SERPENT"; }
// Reset cipher
Serpent.prototype.reset = function() {}

// Process a block
Serpent.prototype.processBlock = function(input, inOff, inLen) {
  inOff = inOff == null ? 0 : inOff;
  if(this.forEncryption) {
    encryptBlock(this, input, inOff);
  } else {
    decryptBlock(this, input, inOff);
  }
}

var encryptBlock = function(self, block, srcIndex) {
  // Decode the integers
  var a = Long.fromNumber(util.decodeUInt32R(block, srcIndex)).getLowBitsUnsigned();
  var b = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 4)).getLowBitsUnsigned();
  var c = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 8)).getLowBitsUnsigned();
  var d = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 12)).getLowBitsUnsigned();
  var e = 0;

  var k = self.key;
  var values = [k, [a, b, c, d, e]];  
  var index = 0;
  var i = 1;
  
  do {
    values = beforeS0(values, index, KX);
    values = beforeS0(values, index, S0);
    values = afterS0(values, index, LT);
    values = afterS0(values, index, KX);
    values = afterS0(values, index, S1);
    values = afterS1(values, index, LT);
    values = afterS1(values, index, KX);
    values = afterS1(values, index, S2);
    values = afterS2(values, index, LT);
    values = afterS2(values, index, KX);
    values = afterS2(values, index, S3);
    values = afterS3(values, index, LT);
    values = afterS3(values, index, KX);
    values = afterS3(values, index, S4);
    values = afterS4(values, index, LT);
    values = afterS4(values, index, KX);
    values = afterS4(values, index, S5);
    values = afterS5(values, index, LT);
    values = afterS5(values, index, KX);
    values = afterS5(values, index, S6);
    values = afterS6(values, index, LT);
    values = afterS6(values, index, KX);
    values = afterS6(values, index, S7);

    if(i == 4) {
      break;
    }

    ++i;
    values[1][2] = values[1][1];
    values[1][1] = values[1][4];
    values[1][4] = values[1][3];
    values[1][3] = values[1][0];
    values[1][0] = values[1][4];
    index = index + 32;

    values = beforeS0(values, index, LT);
  } while(true)

  values = afterS7(values, index, KX);
  // Unpack the variables for easier readability
  a = values[1][0];
  b = values[1][1];
  c = values[1][2];
  d = values[1][3];
  e = values[1][4];

  // Return the encrypted bytes
  util.inPlaceEncodeUInt32R(d, block, srcIndex);
  util.inPlaceEncodeUInt32R(e, block, srcIndex + 4);
  util.inPlaceEncodeUInt32R(b, block, srcIndex + 8);
  util.inPlaceEncodeUInt32R(a, block, srcIndex + 12);
}

var decryptBlock = function(self, block, srcIndex) {
  // Decode the integers
  var a = Long.fromNumber(util.decodeUInt32R(block, srcIndex)).getLowBitsUnsigned();
  var b = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 4)).getLowBitsUnsigned();
  var c = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 8)).getLowBitsUnsigned();
  var d = Long.fromNumber(util.decodeUInt32R(block, srcIndex + 12)).getLowBitsUnsigned();
  var e = 0;

  var k = self.key;
  var values = [k, [a, b, c, d, e]];  
  var index = 96;
  var i = 4;
  
  values = beforeI7(values, index, KX);
  
  do {
    // If we are done with the start
    if(i < 4) {
      values[1][2] = values[1][1];
      values[1][1] = values[1][3];
      values[1][3] = values[1][4];
      index = index - 32;      
      values = beforeI7(values, index, ILT);
    }

    values = beforeI7(values, index, I7);
    values = afterI7(values, index, KX);
    values = afterI7(values, index, ILT);
    values = afterI7(values, index, I6);
    values = afterI6(values, index, KX);
    values = afterI6(values, index, ILT);
    values = afterI6(values, index, I5);
    values = afterI5(values, index, KX);
    values = afterI5(values, index, ILT);
    values = afterI5(values, index, I4);
    values = afterI4(values, index, KX);
    values = afterI4(values, index, ILT);
    values = afterI4(values, index, I3);
    values = afterI3(values, index, KX);
    values = afterI3(values, index, ILT);
    values = afterI3(values, index, I2);
    values = afterI2(values, index, KX);
    values = afterI2(values, index, ILT);
    values = afterI2(values, index, I1);
    values = afterI1(values, index, KX);
    values = afterI1(values, index, ILT);
    values = afterI1(values, index, I0);
    values = afterI0(values, index, KX);
    --i;
  } while(i != 0)

  // Unpack the variables for easier readability
  a = values[1][0];
  b = values[1][1];
  c = values[1][2];
  d = values[1][3];
  e = values[1][4];

  // Return the encrypted bytes
  util.inPlaceEncodeUInt32R(a, block, srcIndex);
  util.inPlaceEncodeUInt32R(d, block, srcIndex + 4);
  util.inPlaceEncodeUInt32R(b, block, srcIndex + 8);
  util.inPlaceEncodeUInt32R(e, block, srcIndex + 12);
}

var beforeI7 = Serpent.beforeI7 = function(values, index, func) {
  var val = func(8, index, values[0], values[1][0], values[1][1], values[1][2], values[1][3], values[1][4]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][2] = val[2], values[1][3] = val[3], values[1][4] = val[4];
  return values;      
}

var afterI0 = Serpent.afterI0 = function(values, index, func) {
  var val = func(0, index, values[0], values[1][0], values[1][3], values[1][1], values[1][4], values[1][2]);
  values[1][0] = val[0], values[1][3] = val[1], values[1][1] = val[2], values[1][4] = val[3], values[1][2] = val[4];
  return values;      
}

var afterI1 = Serpent.afterI1 = function(values, index, func) {
  var val = func(1, index, values[0], values[1][0], values[1][1], values[1][2], values[1][4], values[1][3]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][2] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;      
}

var afterI2 = Serpent.afterI2 = function(values, index, func) {
  var val = func(2, index, values[0], values[1][1], values[1][3], values[1][4], values[1][2], values[1][0]);
  values[1][1] = val[0], values[1][3] = val[1], values[1][4] = val[2], values[1][2] = val[3], values[1][0] = val[4];
  return values;      
}

var afterI3 = Serpent.afterI3 = function(values, index, func) {
  var val = func(3, index, values[0], values[1][0], values[1][1], values[1][4], values[1][2], values[1][3]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][4] = val[2], values[1][2] = val[3], values[1][3] = val[4];
  return values;      
}

var afterI4 = Serpent.afterI4 = function(values, index, func) {
  var val = func(4, index, values[0], values[1][1], values[1][2], values[1][4], values[1][0], values[1][3]);
  values[1][1] = val[0], values[1][2] = val[1], values[1][4] = val[2], values[1][0] = val[3], values[1][3] = val[4];
  return values;      
}

var afterI5 = Serpent.afterI5 = function(values, index, func) {
  var val = func(5, index, values[0], values[1][1], values[1][3], values[1][4], values[1][2], values[1][0]);
  values[1][1] = val[0], values[1][3] = val[1], values[1][4] = val[2], values[1][2] = val[3], values[1][0] = val[4];
  return values;      
}

var afterI6 = Serpent.afterI6 = function(values, index, func) {
  var val = func(6, index, values[0], values[1][0], values[1][1], values[1][2], values[1][4], values[1][3]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][2] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;      
}

var afterI7 = Serpent.afterI7 = function(values, index, func) {
  var val = func(7, index, values[0], values[1][3], values[1][0], values[1][1], values[1][4], values[1][2]);
  values[1][3] = val[0], values[1][0] = val[1], values[1][1] = val[2], values[1][4] = val[3], values[1][2] = val[4];
  return values;      
}

var beforeS0 = Serpent.beforeS0 = function(values, index, func) {
  var val = func(0, index, values[0], values[1][0], values[1][1], values[1][2], values[1][3], values[1][4]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][2] = val[2], values[1][3] = val[3], values[1][4] = val[4];
  return values;      
}

var afterS0 = Serpent.afterS0 = function(values, index, func) {
  var val = func(1, index, values[0], values[1][1], values[1][4], values[1][2], values[1][0], values[1][3]);
  values[1][1] = val[0], values[1][4] = val[1], values[1][2] = val[2], values[1][0] = val[3], values[1][3] = val[4];
  return values;      
}

var afterS1 = Serpent.afterS1 = function(values, index, func) {
  var val = func(2, index, values[0], values[1][2], values[1][1], values[1][0], values[1][4], values[1][3]);
  values[1][2] = val[0], values[1][1] = val[1], values[1][0] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;    
}

var afterS2 = Serpent.afterS2 = function(values, index, func) {
  var val = func(3, index, values[0], values[1][0], values[1][4], values[1][1], values[1][3], values[1][2]);
  values[1][0] = val[0], values[1][4] = val[1], values[1][1] = val[2], values[1][3] = val[3], values[1][2] = val[4];
  return values;
}

var afterS3 = Serpent.afterS3 = function(values, index, func) {
  var val = func(4, index, values[0], values[1][4], values[1][1], values[1][3], values[1][2], values[1][0]);
  values[1][4] = val[0], values[1][1] = val[1], values[1][3] = val[2], values[1][2] = val[3], values[1][0] = val[4];
  return values;  
}

var afterS4 = Serpent.afterS4 = function(values, index, func) {
  var val = func(5, index, values[0], values[1][1], values[1][0], values[1][4], values[1][2], values[1][3]);
  values[1][1] = val[0], values[1][0] = val[1], values[1][4] = val[2], values[1][2] = val[3], values[1][3] = val[4];
  return values;  
}

var afterS5 = Serpent.afterS5 = function(values, index, func) {
  var val = func(6, index, values[0], values[1][0], values[1][2], values[1][1], values[1][4], values[1][3]);
  values[1][0] = val[0], values[1][2] = val[1], values[1][1] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;  
}

var afterS6 = Serpent.afterS6 = function(values, index, func) {
  var val = func(7, index, values[0], values[1][0], values[1][2], values[1][3], values[1][1], values[1][4]);
  values[1][0] = val[0], values[1][2] = val[1], values[1][3] = val[2], values[1][1] = val[3], values[1][4] = val[4];
  return values;  
}

var afterS7 = Serpent.afterS7 = function(values, index, func) {
  var val = func(8, index, values[0], values[1][3], values[1][4], values[1][1], values[1][0], values[1][2]);
  values[1][3] = val[0], values[1][4] = val[1], values[1][1] = val[2], values[1][0] = val[3], values[1][2] = val[4];
  return values;  
}

var I0 = Serpent.I0 = function(i, index, k, r0, r1, r2, r3, r4) {
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();
  r4 = r1;
  r1 = Long.fromNumber(r1 | r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r4).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r1).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I1 = Serpent.I1 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r1;
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r4).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I2 = Serpent.I2 = function(i, index, k, r0, r1, r2, r3, r4) {
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r4 = r3;
  r3 = Long.fromNumber(r3 & r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 & r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(~r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I3 = Serpent.I3 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r2;
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 | r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I4 = Serpent.I4 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r2;
  r2 = Long.fromNumber(r2 & r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(~r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I5 = Serpent.I5 = function(i, index, k, r0, r1, r2, r3, r4) {
  r1 = Long.fromNumber(~r1).getLowBitsUnsigned();
  r4 = r3;
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 | r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I6 = Serpent.I6 = function(i, index, k, r0, r1, r2, r3, r4) {
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r4 = r2;
  r2 = Long.fromNumber(r2 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var I7 = Serpent.I7 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r2;  
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r4).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r4).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];    
}

// inverse linear transformation
var ILT = Serpent.ILT = function(r, index, k, a, b, c, d, e) {
  c = Long.fromNumber(util.rotr(c, 22)).getLowBitsUnsigned();
  a = Long.fromNumber(util.rotr(a, 5)).getLowBitsUnsigned();
  c = Long.fromNumber(c ^ (d ^ (b << 7))).getLowBitsUnsigned();
  a = Long.fromNumber(a ^ (b ^ d)).getLowBitsUnsigned();
  b = Long.fromNumber(util.rotr(b, 1)).getLowBitsUnsigned();
  d = Long.fromNumber(util.rotr(d, 7) ^ c ^ (a << 3)).getLowBitsUnsigned();
  b = Long.fromNumber(b ^ a ^ c).getLowBitsUnsigned();
  c = Long.fromNumber(util.rotr(c, 3)).getLowBitsUnsigned();
  a = Long.fromNumber(util.rotr(a, 13)).getLowBitsUnsigned();
  return [a, b, c, d, e];
}

var KX = Serpent.KX = function(r, index, k, a, b, c, d, e) {
  a = Long.fromNumber(a ^ k[(4 * r) + 0 + index]).getLowBitsUnsigned();
  b = Long.fromNumber(b ^ k[(4 * r) + 1 + index]).getLowBitsUnsigned();
  c = Long.fromNumber(c ^ k[(4 * r) + 2 + index]).getLowBitsUnsigned();
  d = Long.fromNumber(d ^ k[(4 * r) + 3 + index]).getLowBitsUnsigned();
  return [a, b, c, d, e];
}

var LK = Serpent.LK = function(r, index, k, a, b, c, d, e) {  
  a = k[(8 - r)*4 + 0 + index];
  b = k[(8 - r)*4 + 1 + index];
  c = k[(8 - r)*4 + 2 + index];
  d = k[(8 - r)*4 + 3 + index];
  return [a, b, c, d, e];
}

// linear transformation
var LT = Serpent.LT = function(r, index, k, a, b, c, d, e) {
  a = Long.fromNumber(util.rotl(a, 13)).getLowBitsUnsigned();
  c = Long.fromNumber(util.rotl(c, 3)).getLowBitsUnsigned();
  d = Long.fromNumber(util.rotl(d ^ c ^ (a << 3), 7)).getLowBitsUnsigned();
  b = Long.fromNumber(util.rotl(b ^ a ^ c, 1)).getLowBitsUnsigned();
  a = Long.fromNumber(util.rotl(a ^ b ^ d, 5)).getLowBitsUnsigned();
  c = Long.fromNumber(util.rotl(c ^ d ^ (b << 7), 22)).getLowBitsUnsigned();
  return [a, b, c, d, e];
}

var SK = Serpent.SK = function(r, index, k, a, b, c, d, e) {
  k[(8 - r)*4 + 4 + index] = a;
  k[(8 - r)*4 + 5 + index] = b;
  k[(8 - r)*4 + 6 + index] = c;
  k[(8 - r)*4 + 7 + index] = d;  
  return [a, b, c, d, e];
}

var S0 = Serpent.S0 = function(i, index, k, r0, r1, r2, r3, r4) {
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r4 = r1;
  r1 = Long.fromNumber(r1 & r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r4).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 | r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];    
}

var S1 = Serpent.S1 = function(i, index, k, r0, r1, r2, r3, r4) {
  r0 = Long.fromNumber(~r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();
  r4 = r0;
  r0 = Long.fromNumber(r0 & r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r4).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var S2 = Serpent.S2 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r0;
  r0 = Long.fromNumber(r0 & r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 | r4).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r1 = r3;
  r3 = Long.fromNumber(r3 | r4).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];  
}

var S3 = Serpent.S3 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r0;
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 & r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 & r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 | r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r3).getLowBitsUnsigned();
  r2 = r1;
  r1 = Long.fromNumber(r1 | r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];
}

var S4 = Serpent.S4 = function(i, index, k, r0, r1, r2, r3, r4) {
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(~r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r4 = r1;
  r1 = Long.fromNumber(r1 & r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r3).getLowBitsUnsigned();
  r0 = Long.fromNumber(~r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];
}

var S5 = Serpent.S5 = function(i, index, k, r0, r1, r2, r3, r4) {
  r0 = Long.fromNumber(r0 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(~r3).getLowBitsUnsigned();
  r4 = r1;
  r1 = Long.fromNumber(r1 & r0).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 | r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r1).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 & r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 | r3).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();  
  return [r0, r1, r2, r3, r4];
}

var S6 = Serpent.S6 = function(i, index, k, r0, r1, r2, r3, r4) {
  r2 = Long.fromNumber(~r2).getLowBitsUnsigned();  
  r4 = r3;
  r3 = Long.fromNumber(r3 & r0).getLowBitsUnsigned();  
  r0 = Long.fromNumber(r0 ^ r4).getLowBitsUnsigned();  
  r3 = Long.fromNumber(r3 ^ r2).getLowBitsUnsigned();  
  r2 = Long.fromNumber(r2 | r4).getLowBitsUnsigned();  
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();  
  r2 = Long.fromNumber(r2 ^ r0).getLowBitsUnsigned();  
  r0 = Long.fromNumber(r0 | r1).getLowBitsUnsigned();  
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();  
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();  
  r0 = Long.fromNumber(r0 | r3).getLowBitsUnsigned();  
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();  
  r4 = Long.fromNumber(r4 ^ r3).getLowBitsUnsigned();  
  r4 = Long.fromNumber(r4 ^ r0).getLowBitsUnsigned();  
  r3 = Long.fromNumber(~r3).getLowBitsUnsigned();  
  r2 = Long.fromNumber(r2 & r4).getLowBitsUnsigned();  
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();  
  return [r0, r1, r2, r3, r4];
}

var S7 = Serpent.S7 = function(i, index, k, r0, r1, r2, r3, r4) {
  r4 = r2;
  r2 = Long.fromNumber(r2 & r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r1).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r1).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r0).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 | r4).getLowBitsUnsigned();
  r0 = Long.fromNumber(r0 ^ r2).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r1).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r3).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 & r0).getLowBitsUnsigned();
  r3 = Long.fromNumber(r3 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r2).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 & r0).getLowBitsUnsigned();
  r4 = Long.fromNumber(~r4).getLowBitsUnsigned();
  r2 = Long.fromNumber(r2 ^ r4).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 & r0).getLowBitsUnsigned();
  r1 = Long.fromNumber(r1 ^ r3).getLowBitsUnsigned();
  r4 = Long.fromNumber(r4 ^ r1).getLowBitsUnsigned();
  return [r0, r1, r2, r3, r4];
}