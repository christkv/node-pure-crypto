var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 16;

//
// round 1 left rotates
//
const S11 = 7;
const S12 = 12;
const S13 = 17;
const S14 = 22;

//
// round 2 left rotates
//
const S21 = 5;
const S22 = 9;
const S23 = 14;
const S24 = 20;

//
// round 3 left rotates
//
const S31 = 4;
const S32 = 11;
const S33 = 16;
const S34 = 23;

//
// round 4 left rotates
//
const S41 = 6;
const S42 = 10;
const S43 = 15;
const S44 = 21;

var MD5 = exports.MD5 = function() {
  // Call base class constructor
  BaseDigest.call(this);
    
  // MD5 variables
  this.xOff = 0;
  this.X = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  
  // Reset values
  this.H1 = 0x67452301;
  this.H2 = 0xefcdab89;
  this.H3 = 0x98badcfe;
  this.H4 = 0x10325476;
}

inherits(MD5, BaseDigest);

MD5.prototype.digestSize = function() {
  return DIGEST_LENGTH;
}

MD5.prototype.algorithmName = function() {
  return "MD5";
}

MD5.prototype.processWord = function(src, inOff) {
  this.X[this.xOff++] = (src[inOff] & 0xff) | ((src[inOff + 1] & 0xff) << 8)
      | ((src[inOff + 2] & 0xff) << 16) | ((src[inOff + 3] & 0xff) << 24); 

  if (this.xOff == 16) {
    this.processBlock();
  }  
}

MD5.prototype.processBlock = function() {
  var self = this;
  var a = self.H1;
  var b = self.H2;
  var c = self.H3;
  var d = self.H4;

  //
  // Round 1 - F cycle, 16 times.
  //
  a = util.rotl(a + F(b, c, d) + self.X[ 0] + 0xd76aa478, S11) + b;
  d = util.rotl(d + F(a, b, c) + self.X[ 1] + 0xe8c7b756, S12) + a;
  c = util.rotl(c + F(d, a, b) + self.X[ 2] + 0x242070db, S13) + d;
  b = util.rotl(b + F(c, d, a) + self.X[ 3] + 0xc1bdceee, S14) + c;
  a = util.rotl(a + F(b, c, d) + self.X[ 4] + 0xf57c0faf, S11) + b;
  d = util.rotl(d + F(a, b, c) + self.X[ 5] + 0x4787c62a, S12) + a;
  c = util.rotl(c + F(d, a, b) + self.X[ 6] + 0xa8304613, S13) + d;
  b = util.rotl(b + F(c, d, a) + self.X[ 7] + 0xfd469501, S14) + c;
  a = util.rotl(a + F(b, c, d) + self.X[ 8] + 0x698098d8, S11) + b;
  d = util.rotl(d + F(a, b, c) + self.X[ 9] + 0x8b44f7af, S12) + a;
  c = util.rotl(c + F(d, a, b) + self.X[10] + 0xffff5bb1, S13) + d;
  b = util.rotl(b + F(c, d, a) + self.X[11] + 0x895cd7be, S14) + c;
  a = util.rotl(a + F(b, c, d) + self.X[12] + 0x6b901122, S11) + b;
  d = util.rotl(d + F(a, b, c) + self.X[13] + 0xfd987193, S12) + a;
  c = util.rotl(c + F(d, a, b) + self.X[14] + 0xa679438e, S13) + d;
  b = util.rotl(b + F(c, d, a) + self.X[15] + 0x49b40821, S14) + c;

  //
  // Round 2 - G cycle, 16 times.
  //
  a = util.rotl(a + G(b, c, d) + self.X[ 1] + 0xf61e2562, S21) + b;
  d = util.rotl(d + G(a, b, c) + self.X[ 6] + 0xc040b340, S22) + a;
  c = util.rotl(c + G(d, a, b) + self.X[11] + 0x265e5a51, S23) + d;
  b = util.rotl(b + G(c, d, a) + self.X[ 0] + 0xe9b6c7aa, S24) + c;
  a = util.rotl(a + G(b, c, d) + self.X[ 5] + 0xd62f105d, S21) + b;
  d = util.rotl(d + G(a, b, c) + self.X[10] + 0x02441453, S22) + a;
  c = util.rotl(c + G(d, a, b) + self.X[15] + 0xd8a1e681, S23) + d;
  b = util.rotl(b + G(c, d, a) + self.X[ 4] + 0xe7d3fbc8, S24) + c;
  a = util.rotl(a + G(b, c, d) + self.X[ 9] + 0x21e1cde6, S21) + b;
  d = util.rotl(d + G(a, b, c) + self.X[14] + 0xc33707d6, S22) + a;
  c = util.rotl(c + G(d, a, b) + self.X[ 3] + 0xf4d50d87, S23) + d;
  b = util.rotl(b + G(c, d, a) + self.X[ 8] + 0x455a14ed, S24) + c;
  a = util.rotl(a + G(b, c, d) + self.X[13] + 0xa9e3e905, S21) + b;
  d = util.rotl(d + G(a, b, c) + self.X[ 2] + 0xfcefa3f8, S22) + a;
  c = util.rotl(c + G(d, a, b) + self.X[ 7] + 0x676f02d9, S23) + d;
  b = util.rotl(b + G(c, d, a) + self.X[12] + 0x8d2a4c8a, S24) + c;

  //
  // Round 3 - H cycle, 16 times.
  //
  a = util.rotl(a + H(b, c, d) + self.X[ 5] + 0xfffa3942, S31) + b;
  d = util.rotl(d + H(a, b, c) + self.X[ 8] + 0x8771f681, S32) + a;
  c = util.rotl(c + H(d, a, b) + self.X[11] + 0x6d9d6122, S33) + d;
  b = util.rotl(b + H(c, d, a) + self.X[14] + 0xfde5380c, S34) + c;
  a = util.rotl(a + H(b, c, d) + self.X[ 1] + 0xa4beea44, S31) + b;
  d = util.rotl(d + H(a, b, c) + self.X[ 4] + 0x4bdecfa9, S32) + a;
  c = util.rotl(c + H(d, a, b) + self.X[ 7] + 0xf6bb4b60, S33) + d;
  b = util.rotl(b + H(c, d, a) + self.X[10] + 0xbebfbc70, S34) + c;
  a = util.rotl(a + H(b, c, d) + self.X[13] + 0x289b7ec6, S31) + b;
  d = util.rotl(d + H(a, b, c) + self.X[ 0] + 0xeaa127fa, S32) + a;
  c = util.rotl(c + H(d, a, b) + self.X[ 3] + 0xd4ef3085, S33) + d;
  b = util.rotl(b + H(c, d, a) + self.X[ 6] + 0x04881d05, S34) + c;
  a = util.rotl(a + H(b, c, d) + self.X[ 9] + 0xd9d4d039, S31) + b;
  d = util.rotl(d + H(a, b, c) + self.X[12] + 0xe6db99e5, S32) + a;
  c = util.rotl(c + H(d, a, b) + self.X[15] + 0x1fa27cf8, S33) + d;
  b = util.rotl(b + H(c, d, a) + self.X[ 2] + 0xc4ac5665, S34) + c;

  //
  // Round 4 - K cycle, 16 times.
  //
  a = util.rotl(a + K(b, c, d) + self.X[ 0] + 0xf4292244, S41) + b;
  d = util.rotl(d + K(a, b, c) + self.X[ 7] + 0x432aff97, S42) + a;
  c = util.rotl(c + K(d, a, b) + self.X[14] + 0xab9423a7, S43) + d;
  b = util.rotl(b + K(c, d, a) + self.X[ 5] + 0xfc93a039, S44) + c;
  a = util.rotl(a + K(b, c, d) + self.X[12] + 0x655b59c3, S41) + b;
  d = util.rotl(d + K(a, b, c) + self.X[ 3] + 0x8f0ccc92, S42) + a;
  c = util.rotl(c + K(d, a, b) + self.X[10] + 0xffeff47d, S43) + d;
  b = util.rotl(b + K(c, d, a) + self.X[ 1] + 0x85845dd1, S44) + c;
  a = util.rotl(a + K(b, c, d) + self.X[ 8] + 0x6fa87e4f, S41) + b;
  d = util.rotl(d + K(a, b, c) + self.X[15] + 0xfe2ce6e0, S42) + a;
  c = util.rotl(c + K(d, a, b) + self.X[ 6] + 0xa3014314, S43) + d;
  b = util.rotl(b + K(c, d, a) + self.X[13] + 0x4e0811a1, S44) + c;
  a = util.rotl(a + K(b, c, d) + self.X[ 4] + 0xf7537e82, S41) + b;
  d = util.rotl(d + K(a, b, c) + self.X[11] + 0xbd3af235, S42) + a;
  c = util.rotl(c + K(d, a, b) + self.X[ 2] + 0x2ad7d2bb, S43) + d;
  b = util.rotl(b + K(c, d, a) + self.X[ 9] + 0xeb86d391, S44) + c;

  self.H1 += a;
  self.H2 += b;
  self.H3 += c;
  self.H4 += d;

  //
  // reset the offset and clean out the word buffer.
  //
  self.xOff = 0;
  for (var i = 0; i != self.X.length; i++) {
    self.X[i] = 0;
  }
}

/*
 * F, G, H and I are the basic MD5 functions.
 */
var F = function(u, v, w) {
  return (u & v) | (~u & w);
}

var G = function(u, v, w) {
  return (u & w) | (v & ~w);
}

var H = function(u, v, w) {
  return u ^ v ^ w;
}

var K = function(u, v, w) {
  return v ^ (u | ~w);
}

//
// Common to all digests
MD5.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);

  this.xBufOff = 0;
  for(var i = 0; i < this.xBuf.length; i++) {
    this.xBuf[i] = 0;
  }
  
  // Reset values
  this.H1 = 0x67452301;
  this.H2 = 0xefcdab89;
  this.H3 = 0x98badcfe;
  this.H4 = 0x10325476;  
  
  this.xOff = 0;
  
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }  
}

MD5.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }

  this.X[14] = bitLength.getLowBitsUnsigned();
  this.X[15] = bitLength.shiftRightUnsigned(32).getLowBitsUnsigned();
}

//
// Common to all digests
MD5.prototype.digest = function(encoding) {
  this.finish();
  
  var output = new Array(16);
  util.inPlaceEncodeUInt32R(this.H1, output, 0);
  util.inPlaceEncodeUInt32R(this.H2, output, 4);
  util.inPlaceEncodeUInt32R(this.H3, output, 8);
  util.inPlaceEncodeUInt32R(this.H4, output, 12);
  
  this.reset();
  
  // Return based on encoding
  if(encoding == null || encoding === 'binary') {
    return util.arrayToBinaryString(output);
  } else if(encoding === 'hex') {
    return util.toHex(output);
  } else if(encoding === 'array'){
    return output ;    
  }
}

