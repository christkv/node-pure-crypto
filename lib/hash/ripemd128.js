var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 16;
const BYTE_LENGTH = 16;

var RIPEMD128 = exports.RIPEMD128 = function() {
  // Call base class constructor
  BaseDigest.call(this);
    
  // RIPEMD128 variables
  this.xOff = 0;
  this.X = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  
  // Reset 
  this.reset();
}

inherits(RIPEMD128, BaseDigest);

RIPEMD128.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

RIPEMD128.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

RIPEMD128.prototype.getAlgorithmName = function() {
  return "RIPEMD128";
}

RIPEMD128.prototype.processWord = function(src, inOff) {
  this.X[this.xOff++] = (src[inOff] & 0xff) | ((src[inOff + 1] & 0xff) << 8)
      | ((src[inOff + 2] & 0xff) << 16) | ((src[inOff + 3] & 0xff) << 24); 

  if (this.xOff == 16) {
    this.processBlock();
  }  
}

RIPEMD128.prototype.processBlock = function() {
  var self = this;
  
  var a = aa = this.H0;
  var b = bb = this.H1;
  var c = cc = this.H2;
  var d = dd = this.H3;
  
  //
  // Round 1
  //
  a = F1(a, b, c, d, this.X[ 0], 11);
  d = F1(d, a, b, c, this.X[ 1], 14);
  c = F1(c, d, a, b, this.X[ 2], 15);
  b = F1(b, c, d, a, this.X[ 3], 12);
  a = F1(a, b, c, d, this.X[ 4],  5);
  d = F1(d, a, b, c, this.X[ 5],  8);
  c = F1(c, d, a, b, this.X[ 6],  7);
  b = F1(b, c, d, a, this.X[ 7],  9);
  a = F1(a, b, c, d, this.X[ 8], 11);
  d = F1(d, a, b, c, this.X[ 9], 13);
  c = F1(c, d, a, b, this.X[10], 14);
  b = F1(b, c, d, a, this.X[11], 15);
  a = F1(a, b, c, d, this.X[12],  6);
  d = F1(d, a, b, c, this.X[13],  7);
  c = F1(c, d, a, b, this.X[14],  9);
  b = F1(b, c, d, a, this.X[15],  8);

  //
  // Round 2
  //
  a = F2(a, b, c, d, this.X[ 7],  7);
  d = F2(d, a, b, c, this.X[ 4],  6);
  c = F2(c, d, a, b, this.X[13],  8);
  b = F2(b, c, d, a, this.X[ 1], 13);
  a = F2(a, b, c, d, this.X[10], 11);
  d = F2(d, a, b, c, this.X[ 6],  9);
  c = F2(c, d, a, b, this.X[15],  7);
  b = F2(b, c, d, a, this.X[ 3], 15);
  a = F2(a, b, c, d, this.X[12],  7);
  d = F2(d, a, b, c, this.X[ 0], 12);
  c = F2(c, d, a, b, this.X[ 9], 15);
  b = F2(b, c, d, a, this.X[ 5],  9);
  a = F2(a, b, c, d, this.X[ 2], 11);
  d = F2(d, a, b, c, this.X[14],  7);
  c = F2(c, d, a, b, this.X[11], 13);
  b = F2(b, c, d, a, this.X[ 8], 12);

  //
  // Round 3
  //
  a = F3(a, b, c, d, this.X[ 3], 11);
  d = F3(d, a, b, c, this.X[10], 13);
  c = F3(c, d, a, b, this.X[14],  6);
  b = F3(b, c, d, a, this.X[ 4],  7);
  a = F3(a, b, c, d, this.X[ 9], 14);
  d = F3(d, a, b, c, this.X[15],  9);
  c = F3(c, d, a, b, this.X[ 8], 13);
  b = F3(b, c, d, a, this.X[ 1], 15);
  a = F3(a, b, c, d, this.X[ 2], 14);
  d = F3(d, a, b, c, this.X[ 7],  8);
  c = F3(c, d, a, b, this.X[ 0], 13);
  b = F3(b, c, d, a, this.X[ 6],  6);
  a = F3(a, b, c, d, this.X[13],  5);
  d = F3(d, a, b, c, this.X[11], 12);
  c = F3(c, d, a, b, this.X[ 5],  7);
  b = F3(b, c, d, a, this.X[12],  5);

  //
  // Round 4
  //
  a = F4(a, b, c, d, this.X[ 1], 11);
  d = F4(d, a, b, c, this.X[ 9], 12);
  c = F4(c, d, a, b, this.X[11], 14);
  b = F4(b, c, d, a, this.X[10], 15);
  a = F4(a, b, c, d, this.X[ 0], 14);
  d = F4(d, a, b, c, this.X[ 8], 15);
  c = F4(c, d, a, b, this.X[12],  9);
  b = F4(b, c, d, a, this.X[ 4],  8);
  a = F4(a, b, c, d, this.X[13],  9);
  d = F4(d, a, b, c, this.X[ 3], 14);
  c = F4(c, d, a, b, this.X[ 7],  5);
  b = F4(b, c, d, a, this.X[15],  6);
  a = F4(a, b, c, d, this.X[14],  8);
  d = F4(d, a, b, c, this.X[ 5],  6);
  c = F4(c, d, a, b, this.X[ 6],  5);
  b = F4(b, c, d, a, this.X[ 2], 12);

  //
  // Parallel round 1
  //
  aa = FF4(aa, bb, cc, dd, this.X[ 5],  8);
  dd = FF4(dd, aa, bb, cc, this.X[14],  9);
  cc = FF4(cc, dd, aa, bb, this.X[ 7],  9);
  bb = FF4(bb, cc, dd, aa, this.X[ 0], 11);
  aa = FF4(aa, bb, cc, dd, this.X[ 9], 13);
  dd = FF4(dd, aa, bb, cc, this.X[ 2], 15);
  cc = FF4(cc, dd, aa, bb, this.X[11], 15);
  bb = FF4(bb, cc, dd, aa, this.X[ 4],  5);
  aa = FF4(aa, bb, cc, dd, this.X[13],  7);
  dd = FF4(dd, aa, bb, cc, this.X[ 6],  7);
  cc = FF4(cc, dd, aa, bb, this.X[15],  8);
  bb = FF4(bb, cc, dd, aa, this.X[ 8], 11);
  aa = FF4(aa, bb, cc, dd, this.X[ 1], 14);
  dd = FF4(dd, aa, bb, cc, this.X[10], 14);
  cc = FF4(cc, dd, aa, bb, this.X[ 3], 12);
  bb = FF4(bb, cc, dd, aa, this.X[12],  6);

  //
  // Parallel round 2
  //
  aa = FF3(aa, bb, cc, dd, this.X[ 6],  9);
  dd = FF3(dd, aa, bb, cc, this.X[11], 13);
  cc = FF3(cc, dd, aa, bb, this.X[ 3], 15);
  bb = FF3(bb, cc, dd, aa, this.X[ 7],  7);
  aa = FF3(aa, bb, cc, dd, this.X[ 0], 12);
  dd = FF3(dd, aa, bb, cc, this.X[13],  8);
  cc = FF3(cc, dd, aa, bb, this.X[ 5],  9);
  bb = FF3(bb, cc, dd, aa, this.X[10], 11);
  aa = FF3(aa, bb, cc, dd, this.X[14],  7);
  dd = FF3(dd, aa, bb, cc, this.X[15],  7);
  cc = FF3(cc, dd, aa, bb, this.X[ 8], 12);
  bb = FF3(bb, cc, dd, aa, this.X[12],  7);
  aa = FF3(aa, bb, cc, dd, this.X[ 4],  6);
  dd = FF3(dd, aa, bb, cc, this.X[ 9], 15);
  cc = FF3(cc, dd, aa, bb, this.X[ 1], 13);
  bb = FF3(bb, cc, dd, aa, this.X[ 2], 11);

  //
  // Parallel round 3
  //
  aa = FF2(aa, bb, cc, dd, this.X[15],  9);
  dd = FF2(dd, aa, bb, cc, this.X[ 5],  7);
  cc = FF2(cc, dd, aa, bb, this.X[ 1], 15);
  bb = FF2(bb, cc, dd, aa, this.X[ 3], 11);
  aa = FF2(aa, bb, cc, dd, this.X[ 7],  8);
  dd = FF2(dd, aa, bb, cc, this.X[14],  6);
  cc = FF2(cc, dd, aa, bb, this.X[ 6],  6);
  bb = FF2(bb, cc, dd, aa, this.X[ 9], 14);
  aa = FF2(aa, bb, cc, dd, this.X[11], 12);
  dd = FF2(dd, aa, bb, cc, this.X[ 8], 13);
  cc = FF2(cc, dd, aa, bb, this.X[12],  5);
  bb = FF2(bb, cc, dd, aa, this.X[ 2], 14);
  aa = FF2(aa, bb, cc, dd, this.X[10], 13);
  dd = FF2(dd, aa, bb, cc, this.X[ 0], 13);
  cc = FF2(cc, dd, aa, bb, this.X[ 4],  7);
  bb = FF2(bb, cc, dd, aa, this.X[13],  5);

  //
  // Parallel round 4
  //
  aa = FF1(aa, bb, cc, dd, this.X[ 8], 15);
  dd = FF1(dd, aa, bb, cc, this.X[ 6],  5);
  cc = FF1(cc, dd, aa, bb, this.X[ 4],  8);
  bb = FF1(bb, cc, dd, aa, this.X[ 1], 11);
  aa = FF1(aa, bb, cc, dd, this.X[ 3], 14);
  dd = FF1(dd, aa, bb, cc, this.X[11], 14);
  cc = FF1(cc, dd, aa, bb, this.X[15],  6);
  bb = FF1(bb, cc, dd, aa, this.X[ 0], 14);
  aa = FF1(aa, bb, cc, dd, this.X[ 5],  6);
  dd = FF1(dd, aa, bb, cc, this.X[12],  9);
  cc = FF1(cc, dd, aa, bb, this.X[ 2], 12);
  bb = FF1(bb, cc, dd, aa, this.X[13],  9);
  aa = FF1(aa, bb, cc, dd, this.X[ 9], 12);
  dd = FF1(dd, aa, bb, cc, this.X[ 7],  5);
  cc = FF1(cc, dd, aa, bb, this.X[10], 15);
  bb = FF1(bb, cc, dd, aa, this.X[14],  8);

  dd += c + this.H1;               // final result for H0

  //
  // combine the results
  //
  this.H1 = this.H2 + d + aa;
  this.H2 = this.H3 + a + bb;
  this.H3 = this.H0 + b + cc;
  this.H0 = dd;

  //
  // reset the offset and clean out the word buffer.
  //
  this.xOff = 0;
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }  
}

/*
 * f1,f2,f3,f4 are the basic RIPEMD128 functions.
 */

// F
var f1 = function(x, y, z) {
  return x ^ y ^ z;  
}

// G
var f2 = function(x, y, z) {
  return (x & y) | (~x & z);
}

// H
var f3 = function(x, y, z) {
  return (x | ~y) ^ z;
}

// I
var f4 = function(x, y, z) {
  return (x & z) | (y & ~z);
}

var F1 = function(a, b, c, d, x, s) {
  return util.rotl(a + f1(b, c, d) + x, s);
}

var F2 = function(a, b, c, d, x, s) {
  return util.rotl(a + f2(b, c, d) + x + 0x5a827999, s);
}

var F3 = function(a, b, c, d, x, s) {
  return util.rotl(a + f3(b, c, d) + x + 0x6ed9eba1, s);
}

var F4 = function(a, b, c, d, x, s) {
  return util.rotl(a + f4(b, c, d) + x + 0x8f1bbcdc, s);
}

var FF1 = function(a, b, c, d, x, s) {
  return util.rotl(a + f1(b, c, d) + x, s);
}

var FF2 = function(a, b, c, d, x, s) {
  return util.rotl(a + f2(b, c, d) + x + 0x6d703ef3, s);
}

var FF3 = function(a, b, c, d, x, s) {
  return util.rotl(a + f3(b, c, d) + x + 0x5c4dd124, s);
}

var FF4 = function(a, b, c, d, x, s) {
  return util.rotl(a + f4(b, c, d) + x + 0x50a28be6, s);
}

//
// Common to all digests
RIPEMD128.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);

  this.xBufOff = 0;
  for(var i = 0; i < this.xBuf.length; i++) {
    this.xBuf[i] = 0;
  }
  
  // Reset values
  this.H0 = 0x67452301;
  this.H1 = 0xefcdab89;
  this.H2 = 0x98badcfe;
  this.H3 = 0x10325476;  
  
  this.xOff = 0;
  
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }  
}

RIPEMD128.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }

  this.X[14] = bitLength.getLowBitsUnsigned();
  this.X[15] = bitLength.shiftRightUnsigned(32).getLowBitsUnsigned();
}

//
// Common to all digests
RIPEMD128.prototype.doFinal = function(output, index) {
  this.finish();
  index = index == null ? 0 : index;
  // Encode in place
  util.inPlaceEncodeUInt32R(this.H0, output, index + 0);
  util.inPlaceEncodeUInt32R(this.H1, output, index + 4);
  util.inPlaceEncodeUInt32R(this.H2, output, index + 8);
  util.inPlaceEncodeUInt32R(this.H3, output, index + 12);  
  this.reset();  
  // Return based on encoding
  return DIGEST_LENGTH;
}

