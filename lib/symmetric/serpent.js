var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// Serpent Cipher
const BlockSize = 16;
// Global variables
// var a = 0, b = 0, c = 0, d = 0, e = 0;

var Serpent = exports.Serpent = function(key, rounds) {
  // Set default number of rounds to 32
  rounds = rounds == null ? 32 : rounds;
  // key = key.reverse()
  var k0 = this.key = [0, 0, 0, 0, 0, 0, 0, 0];
  var k = new Array(32);
  var numberOfWords = key.length/4;
  var keyLength = key.length;

  for(var i = 0; i < numberOfWords; i++) {
    k0[i] = Long.fromNumber(util.decodeUInt32(key.slice((i*4), (i*4 + 4)).reverse(), 0)).getLowBitsUnsigned();
  }
  
  if(key.length < 32) {
    k0[keyLength/4] = k0[keyLength/4] | (1 << ((keyLength % 4) * 8));
  }
  
  var t = k0[7];
  // Let's modify the key
  for(var i = 0; i < 8; ++i) {
    k[i] = k0[i] = t = Long.fromNumber(util.rotl(k0[i] ^ k0[(i + 3)%8] ^ k0[(i + 5)%8] ^ t ^ 0x9e3779b9 ^ i, 11)).getLowBitsUnsigned();
  }
  
  // debug("------------------------------------------------------------ key 0")
  // debug(inspect(k))

  for(var i = 8; i < 4*(rounds+1); ++i) {
    // var x = Long.fromNumber(k[i - 8]).xor(k[i - 5]).xor(k[i - 3]).xor(t).xor(0x9e3779b9).xor(i).getLowBitsUnsigned();
    // k[i] = t = Long.fromNumber(util.rotl(x, 11)).getLowBitsUnsigned();
    
    // debug("------------------------------------------------------")
    // debug("  t = " + t)
    // debug("  i = " + i)
    // debug("  r = " + Long.fromNumber(k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ t ^ 0x9e3779b9 ^ i).getLowBitsUnsigned());
    var r = Long.fromNumber(k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ t ^ 0x9e3779b9 ^ i).getLowBitsUnsigned();
    // k[i] = t = Long.fromNumber(util.rotl(k[i - 8] ^ k[i - 5] ^ k[i - 3] ^ t ^ 0x9e3779b9 ^ i), 11).getLowBitsUnsigned();
    k[i] = t = Long.fromNumber(util.rotl(r, 11)).getLowBitsUnsigned();
    // debug("  k[i - 8] = " + k[i - 8])
    // debug("  k[i - 5] = " + k[i - 5])
    // debug("  k[i - 3] = " + k[i - 3])
    // debug("  t = " + t)
  }
  
  // slide the key 20 spaces to the right
  k = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].concat(k);
  // index in k
  var index = 0;
  // Declare some place holders
  // var a = 0, b = 0, c = 0, d = 0, e = 0;
  var values = [k, [0, 0, 0, 0, 0]];
  for(var i = 0; i < rounds/8; i++) {
    // // afterS2(LK)
    // var r = LK(3, k, a, e, b, d, c);
    // a = r[0], e = r[1], b = r[2], d = r[3], c = r[4];
    // // afterS2(S3)
    // r = S3(3, k, a, e, b, d, c);
    // a = r[0], e = r[1], b = r[2], d = r[3], c = r[4];

    values = afterS2(values, index, LK);
    debug("=================================================== round:" + i);
    debug("    afterS2(LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS2(values, index, S3);

    debug("    afterS2(S3) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS3(values, index, SK);

    debug("    afterS3(values, SK) =====");
    debug("      k[" + (index + 20) + "] = " + values[0][index + 20]);
    debug("      k[" + (index + 21) + "] = " + values[0][index + 21]);
    debug("      k[" + (index + 22) + "] = " + values[0][index + 22]);
    debug("      k[" + (index + 23) + "] = " + values[0][index + 23]);

    values = afterS1(values, index, LK);

    debug("    afterS1(values, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS1(values, index, S2);

    debug("    afterS1(values, S2) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);
    
    values = afterS2(values, index, SK);

    debug("    afterS3(values, SK) =====");
    debug("      k[" + (index + 24) + "] = " + values[0][index + 24]);
    debug("      k[" + (index + 25) + "] = " + values[0][index + 25]);
    debug("      k[" + (index + 26) + "] = " + values[0][index + 26]);
    debug("      k[" + (index + 27) + "] = " + values[0][index + 27]);

    values = afterS0(values, index, LK);

    debug("    afterS0(values, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS0(values, index, S1);

    debug("    afterS0(values, S1) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);
    
    values = afterS1(values, index, SK);

    debug("    afterS1(values, SK) =====");
    debug("      k[" + (index + 28) + "] = " + values[0][index + 28]);
    debug("      k[" + (index + 29) + "] = " + values[0][index + 29]);
    debug("      k[" + (index + 30) + "] = " + values[0][index + 30]);
    debug("      k[" + (index + 31) + "] = " + values[0][index + 31]);

    values = beforeS0(values, index, LK);

    debug("    beforeS0(values, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = beforeS0(values, index, S0);

    debug("    beforeS0(values, S0) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS0(values, index, SK);

    debug("    afterS0(values, SK) =====");
    debug("      k[" + (index + 36) + "] = " + values[0][index + 36]);
    debug("      k[" + (index + 37) + "] = " + values[0][index + 37]);
    debug("      k[" + (index + 38) + "] = " + values[0][index + 38]);
    debug("      k[" + (index + 39) + "] = " + values[0][index + 39]);
    
    // Adjust the index
    index = index + (8*4);
    
    values = afterS6(values, index, LK);

    debug("    afterS6(values, index, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS6(values, index, S7);

    debug("    afterS6(values, index, S7) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);
    
    values = afterS7(values, index, SK);

    debug("    afterS7(values, SK) =====");
    debug("      k[" + (index + 4) + "] = " + values[0][index + 4]);
    debug("      k[" + (index + 5) + "] = " + values[0][index + 5]);
    debug("      k[" + (index + 6) + "] = " + values[0][index + 6]);
    debug("      k[" + (index + 7) + "] = " + values[0][index + 7]);

    values = afterS5(values, index, LK);

    debug("    afterS5(values, index, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS5(values, index, S6);

    debug("    afterS5(values, index, S6) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS6(values, index, SK);

    debug("    afterS6(values, SK) =====");
    debug("      k[" + (index + 8) + "] = " + values[0][index + 8]);
    debug("      k[" + (index + 9) + "] = " + values[0][index + 9]);
    debug("      k[" + (index + 10) + "] = " + values[0][index + 10]);
    debug("      k[" + (index + 11) + "] = " + values[0][index + 11]);

    values = afterS4(values, index, LK);

    debug("    afterS4(values, index, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS4(values, index, S5);

    debug("    afterS4(values, index, S5) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);
    
    values = afterS5(values, index, SK);

    debug("    afterS5(values, SK) =====");
    debug("      k[" + (index + 16) + "] = " + values[0][index + 16]);
    debug("      k[" + (index + 17) + "] = " + values[0][index + 17]);
    debug("      k[" + (index + 18) + "] = " + values[0][index + 18]);
    debug("      k[" + (index + 19) + "] = " + values[0][index + 19]);    

    values = afterS3(values, index, LK);

    debug("    afterS3(values, index, LK) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS3(values, index, S4);

    debug("    afterS3(values, index, S4) =====");
    debug("      a = " + values[1][0]);
    debug("      b = " + values[1][1]);
    debug("      c = " + values[1][2]);
    debug("      d = " + values[1][3]);
    debug("      e = " + values[1][4]);

    values = afterS4(values, index, SK);

    debug("    afterS4(values, SK) =====");
    debug("      k[" + (index + 18) + "] = " + values[0][index + 18]);
    debug("      k[" + (index + 19) + "] = " + values[0][index + 19]);
    debug("      k[" + (index + 20) + "] = " + values[0][index + 20]);
    debug("      k[" + (index + 21) + "] = " + values[0][index + 21]);    
  }
  
  values = afterS2(values, index, LK);

  debug("    afterS2(values, index, LK) =====");
  debug("      a = " + values[1][0]);
  debug("      b = " + values[1][1]);
  debug("      c = " + values[1][2]);
  debug("      d = " + values[1][3]);
  debug("      e = " + values[1][4]);

  values = afterS2(values, index, S3);

  debug("    afterS2(values, index, S3) =====");
  debug("      a = " + values[1][0]);
  debug("      b = " + values[1][1]);
  debug("      c = " + values[1][2]);
  debug("      d = " + values[1][3]);
  debug("      e = " + values[1][4]);
  
  values = afterS3(values, index, SK);

  debug("    afterS3(values, index, S3) =====");
  debug("      k[" + (index + 20) + "] = " + values[0][index + 20]);
  debug("      k[" + (index + 21) + "] = " + values[0][index + 21]);
  debug("      k[" + (index + 22) + "] = " + values[0][index + 22]);
  debug("      k[" + (index + 23) + "] = " + values[0][index + 23]);    

  // debug("------------------------------------------------------------ key 1")
  // debug(inspect(k))
}

var beforeS0 = function(values, index, func) {
  var val = func(0, index, values[0], values[1][0], values[1][1], values[1][2], values[1][3], values[1][4]);
  values[1][0] = val[0], values[1][1] = val[1], values[1][2] = val[2], values[1][3] = val[3], values[1][4] = val[4];
  return values;      
}

var afterS0 = function(values, index, func) {
  var val = func(1, index, values[0], values[1][1], values[1][4], values[1][2], values[1][0], values[1][3]);
  values[1][1] = val[0], values[1][4] = val[1], values[1][2] = val[2], values[1][0] = val[3], values[1][3] = val[4];
  return values;      
}

var afterS1 = function(values, index, func) {
  var val = func(2, index, values[0], values[1][2], values[1][1], values[1][0], values[1][4], values[1][3]);
  values[1][2] = val[0], values[1][1] = val[1], values[1][0] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;    
}

var afterS2 = function(values, index, func) {
  var val = func(3, index, values[0], values[1][0], values[1][4], values[1][1], values[1][3], values[1][2]);
  values[1][0] = val[0], values[1][4] = val[1], values[1][1] = val[2], values[1][3] = val[3], values[1][2] = val[4];
  return values;
}

var afterS3 = function(values, index, func) {
  var val = func(4, index, values[0], values[1][4], values[1][1], values[1][3], values[1][2], values[1][0]);
  values[1][4] = val[0], values[1][1] = val[1], values[1][3] = val[2], values[1][2] = val[3], values[1][0] = val[4];
  return values;  
}

var afterS4 = function(values, index, func) {
  var val = func(5, index, values[0], values[1][1], values[1][0], values[1][4], values[1][2], values[1][3]);
  values[1][1] = val[0], values[1][0] = val[1], values[1][4] = val[2], values[1][2] = val[3], values[1][3] = val[4];
  return values;  
}

var afterS5 = function(values, index, func) {
  var val = func(6, index, values[0], values[1][0], values[1][2], values[1][1], values[1][4], values[1][3]);
  values[1][0] = val[0], values[1][2] = val[1], values[1][1] = val[2], values[1][4] = val[3], values[1][3] = val[4];
  return values;  
}

var afterS6 = function(values, index, func) {
  var val = func(7, index, values[0], values[1][0], values[1][2], values[1][3], values[1][1], values[1][4]);
  values[1][0] = val[0], values[1][2] = val[1], values[1][3] = val[2], values[1][1] = val[3], values[1][4] = val[4];
  return values;  
}

var afterS7 = function(values, index, func) {
  var val = func(8, index, values[0], values[1][3], values[1][4], values[1][1], values[1][0], values[1][2]);
  values[1][3] = val[0], values[1][4] = val[1], values[1][1] = val[2], values[1][0] = val[3], values[1][2] = val[4];
  return values;  
}

var LK = function(r, index, k, a, b, c, d, e) {  
  a = k[(8 - r)*4 + 0 + index];
  b = k[(8 - r)*4 + 1 + index];
  c = k[(8 - r)*4 + 2 + index];
  d = k[(8 - r)*4 + 3 + index];
  return [a, b, c, d, e];
}

var SK = function(r, index, k, a, b, c, d, e) {
  k[(8 - r)*4 + 4 + index] = a;
  k[(8 - r)*4 + 5 + index] = b;
  k[(8 - r)*4 + 6 + index] = c;
  k[(8 - r)*4 + 7 + index] = d;  
  return [a, b, c, d, e];
}

var S0 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S1 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S2 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S3 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S4 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S5 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S6 = function(i, index, k, r0, r1, r2, r3, r4) {
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

var S7 = function(i, index, k, r0, r1, r2, r3, r4) {
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


Serpent.prototype.getBlockSize = function() {
  return BlockSize;
}

Serpent.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptBlock(src.slice(index, index + BlockSize));
}

Serpent.prototype.encryptBlock = function(block) {
}

Serpent.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.decryptBlock(src.slice(index, index + BlockSize));
}

Serpent.prototype.decryptBlock = function(block) {
}
