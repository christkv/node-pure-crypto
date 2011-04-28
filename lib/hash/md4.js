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
const S11 = 3;
const S12 = 7;
const S13 = 11;
const S14 = 19;

//
// round 2 left rotates
//
const S21 = 3;
const S22 = 5;
const S23 = 9;
const S24 = 13;

//
// round 3 left rotates
//
const S31 = 3;
const S32 = 9;
const S33 = 11;
const S34 = 15;

var MD4 = exports.MD4 = function() {
  // Call base class constructor
  BaseDigest.call(this);
  // Setup MD4
  this.H1 = 0x67452301;
  this.H2 = 0xefcdab89;
  this.H3 = 0x98badcfe;
  this.H4 = 0x10325476;
  this.X = new Array(16);
  this.xOff = 0;
  // Reset state
  this.reset();
}

inherits(MD4, BaseDigest);

MD4.prototype.digestSize = function() {
  return DIGEST_LENGTH;
}

MD4.prototype.processWord = function(src, inOff) {
  this.X[this.xOff++] = (src[inOff] & 0xff) | ((src[inOff + 1] & 0xff) << 8)
      | ((src[inOff + 2] & 0xff) << 16) | ((src[inOff + 3] & 0xff) << 24); 

  if (this.xOff == 16) {
    this.processBlock();
  }
}

MD4.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }

  this.X[14] = (bitLength & 0xffffffff);
  this.X[15] = Long.fromNumber(bitLength).shiftRightUnsigned(32).getLowBitsUnsigned();
}

MD4.prototype.processBlock = function() {
  var self = this;
  var a = self.H1;
  var b = self.H2;
  var c = self.H3;
  var d = self.H4;

  //
  // Round 1 - F cycle, 16 times.
  //
  a = util.rotl(a + F(b, c, d) + self.X[ 0], S11);
  d = util.rotl(d + F(a, b, c) + self.X[ 1], S12);
  c = util.rotl(c + F(d, a, b) + self.X[ 2], S13);
  b = util.rotl(b + F(c, d, a) + self.X[ 3], S14);
  a = util.rotl(a + F(b, c, d) + self.X[ 4], S11);
  d = util.rotl(d + F(a, b, c) + self.X[ 5], S12);
  c = util.rotl(c + F(d, a, b) + self.X[ 6], S13);
  b = util.rotl(b + F(c, d, a) + self.X[ 7], S14);
  a = util.rotl(a + F(b, c, d) + self.X[ 8], S11);
  d = util.rotl(d + F(a, b, c) + self.X[ 9], S12);
  c = util.rotl(c + F(d, a, b) + self.X[10], S13);
  b = util.rotl(b + F(c, d, a) + self.X[11], S14);
  a = util.rotl(a + F(b, c, d) + self.X[12], S11);
  d = util.rotl(d + F(a, b, c) + self.X[13], S12);
  c = util.rotl(c + F(d, a, b) + self.X[14], S13);
  b = util.rotl(b + F(c, d, a) + self.X[15], S14);

  //
  // Round 2 - G cycle, 16 times.
  //
  a = util.rotl(a + G(b, c, d) + self.X[ 0] + 0x5a827999, S21);
  d = util.rotl(d + G(a, b, c) + self.X[ 4] + 0x5a827999, S22);
  c = util.rotl(c + G(d, a, b) + self.X[ 8] + 0x5a827999, S23);
  b = util.rotl(b + G(c, d, a) + self.X[12] + 0x5a827999, S24);
  a = util.rotl(a + G(b, c, d) + self.X[ 1] + 0x5a827999, S21);
  d = util.rotl(d + G(a, b, c) + self.X[ 5] + 0x5a827999, S22);
  c = util.rotl(c + G(d, a, b) + self.X[ 9] + 0x5a827999, S23);
  b = util.rotl(b + G(c, d, a) + self.X[13] + 0x5a827999, S24);
  a = util.rotl(a + G(b, c, d) + self.X[ 2] + 0x5a827999, S21);
  d = util.rotl(d + G(a, b, c) + self.X[ 6] + 0x5a827999, S22);
  c = util.rotl(c + G(d, a, b) + self.X[10] + 0x5a827999, S23);
  b = util.rotl(b + G(c, d, a) + self.X[14] + 0x5a827999, S24);
  a = util.rotl(a + G(b, c, d) + self.X[ 3] + 0x5a827999, S21);
  d = util.rotl(d + G(a, b, c) + self.X[ 7] + 0x5a827999, S22);
  c = util.rotl(c + G(d, a, b) + self.X[11] + 0x5a827999, S23);
  b = util.rotl(b + G(c, d, a) + self.X[15] + 0x5a827999, S24);

  //
  // Round 3 - H cycle, 16 times.
  //
  a = util.rotl(a + H(b, c, d) + self.X[ 0] + 0x6ed9eba1, S31);
  d = util.rotl(d + H(a, b, c) + self.X[ 8] + 0x6ed9eba1, S32);
  c = util.rotl(c + H(d, a, b) + self.X[ 4] + 0x6ed9eba1, S33);
  b = util.rotl(b + H(c, d, a) + self.X[12] + 0x6ed9eba1, S34);
  a = util.rotl(a + H(b, c, d) + self.X[ 2] + 0x6ed9eba1, S31);
  d = util.rotl(d + H(a, b, c) + self.X[10] + 0x6ed9eba1, S32);
  c = util.rotl(c + H(d, a, b) + self.X[ 6] + 0x6ed9eba1, S33);
  b = util.rotl(b + H(c, d, a) + self.X[14] + 0x6ed9eba1, S34);
  a = util.rotl(a + H(b, c, d) + self.X[ 1] + 0x6ed9eba1, S31);
  d = util.rotl(d + H(a, b, c) + self.X[ 9] + 0x6ed9eba1, S32);
  c = util.rotl(c + H(d, a, b) + self.X[ 5] + 0x6ed9eba1, S33);
  b = util.rotl(b + H(c, d, a) + self.X[13] + 0x6ed9eba1, S34);
  a = util.rotl(a + H(b, c, d) + self.X[ 3] + 0x6ed9eba1, S31);
  d = util.rotl(d + H(a, b, c) + self.X[11] + 0x6ed9eba1, S32);
  c = util.rotl(c + H(d, a, b) + self.X[ 7] + 0x6ed9eba1, S33);
  b = util.rotl(b + H(c, d, a) + self.X[15] + 0x6ed9eba1, S34);

  self.H1 += a;
  self.H2 += b;
  self.H3 += c;
  self.H4 += d;

  //
  // reset the offset and clean out the word buffer.
  //
  self.xOff = 0;
  for(var i = 0; i != self.X.length; i++) {
    self.X[i] = 0;
  }  
}

/*
 * F, G, H and I are the basic MD4 functions.
 */
var F = function(u, v, w) {
  return (u & v) | (~u & w);
}

var G = function(u, v, w) {
  return (u & v) | (u & w) | (v & w);
}

var H = function(u, v, w) {
  return u ^ v ^ w;
}

//
// Common to all digests
MD4.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);
  // Setup
  this.H1 = 0x67452301;
  this.H2 = 0xefcdab89;
  this.H3 = 0x98badcfe;
  this.H4 = 0x10325476;
  this.xOff = 0;

  for(var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }
}

MD4.prototype.algorithmName = function() {
  return "MD4";
}

//
// Common to all digests
MD4.prototype.digest = function(encoding) {
  // add padding
  this.finish();
  // Ouput digest
  var output = new Array(16);
  util.inPlaceEncodeUInt32R(this.H1, output, 0);
  util.inPlaceEncodeUInt32R(this.H2, output, 4);
  util.inPlaceEncodeUInt32R(this.H3, output, 8);
  util.inPlaceEncodeUInt32R(this.H4, output, 12);
  // Reset
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
