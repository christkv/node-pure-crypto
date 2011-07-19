var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 32;
const BYTE_LENGTH = 64;

var SHA256 = exports.SHA256 = function() {
  // Call base class constructor
  BaseDigest.call(this);
  // Setup SHA256
  this.X = new Array(64);
  // Reset state
  this.reset();
}

inherits(SHA256, BaseDigest);

SHA256.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

SHA256.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

SHA256.prototype.processWord = function(src, inOff) {
  var n = src[inOff] << 24;
      n |= (src[++inOff] & 0xff) << 16;
      n |= (src[++inOff] & 0xff) << 8;
      n |= (src[++inOff] & 0xff);
  this.X[this.xOff] = n;
  
  if (++this.xOff == 16) {
    this.processBlock();
  }
}

SHA256.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }
  
  this.X[14] = Long.fromNumber(bitLength).shiftRightUnsigned(32).getLowBitsUnsigned();
  this.X[15] = (bitLength & 0xffffffff);
}

//
// Common to all digests
SHA256.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);
  
  // SHA-256 initial hash value
  this.H1 = 0x6a09e667;
  this.H2 = 0xbb67ae85;
  this.H3 = 0x3c6ef372;
  this.H4 = 0xa54ff53a;
  this.H5 = 0x510e527f;
  this.H6 = 0x9b05688c;
  this.H7 = 0x1f83d9ab;
  this.H8 = 0x5be0cd19;

  this.xOff = 0;
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }
}

//
// Common to all digests
SHA256.prototype.doFinal = function(output, index) {
  // add padding
  this.finish();
  index = index == null ? 0 : index;
  // Ouput digest
  util.inPlaceEncodeUInt32(this.H1, output, index + 0);
  util.inPlaceEncodeUInt32(this.H2, output, index + 4);
  util.inPlaceEncodeUInt32(this.H3, output, index + 8);
  util.inPlaceEncodeUInt32(this.H4, output, index + 12);
  util.inPlaceEncodeUInt32(this.H5, output, index + 16);
  util.inPlaceEncodeUInt32(this.H6, output, index + 20);
  util.inPlaceEncodeUInt32(this.H7, output, index + 24);
  util.inPlaceEncodeUInt32(this.H8, output, index + 28);
  // Reset
  this.reset();
  return DIGEST_LENGTH;
}

SHA256.prototype.getAlgorithmName = function() {
  return "SHA-256";
}

SHA256.prototype.processBlock = function() {
  //
  // expand 16 word block into 64 word blocks.
  //
  for(var t = 16; t <= 63; t++) {
    this.X[t] = Theta1(this.X[t - 2]) + this.X[t - 7] + Theta0(this.X[t - 15]) + this.X[t - 16];
  }

  //
  // set up working variables.
  //
  var a = this.H1;
  var b = this.H2;
  var c = this.H3;
  var d = this.H4;
  var e = this.H5;
  var f = this.H6;
  var g = this.H7;
  var h = this.H8;

  var t = 0;     
  for(var i = 0; i < 8; i ++) {
    // t = 8 * i
    h += Sum1(e) + Ch(e, f, g) + K[t] + this.X[t];
    d = Long.fromNumber(d + h).getLowBitsUnsigned();
    h += Sum0(a) + Maj(a, b, c);
    ++t;

    // t = 8 * i + 1
    g += Sum1(d) + Ch(d, e, f) + K[t] + this.X[t];
    c = Long.fromNumber(c + g).getLowBitsUnsigned();
    g += Sum0(h) + Maj(h, a, b);
    ++t;

    // t = 8 * i + 2
    f += Sum1(c) + Ch(c, d, e) + K[t] + this.X[t];
    b = Long.fromNumber(b + f).getLowBitsUnsigned();
    f += Sum0(g) + Maj(g, h, a);
    ++t;

    // t = 8 * i + 3
    e += Sum1(b) + Ch(b, c, d) + K[t] + this.X[t];
    a = Long.fromNumber(a + e).getLowBitsUnsigned();
    e += Sum0(f) + Maj(f, g, h);
    ++t;

    // t = 8 * i + 4
    d += Sum1(a) + Ch(a, b, c) + K[t] + this.X[t];
    h = Long.fromNumber(h + d).getLowBitsUnsigned();
    d += Sum0(e) + Maj(e, f, g);
    ++t;

    // t = 8 * i + 5
    c += Sum1(h) + Ch(h, a, b) + K[t] + this.X[t];
    g = Long.fromNumber(g + c).getLowBitsUnsigned();
    c += Sum0(d) + Maj(d, e, f);
    ++t;

    // t = 8 * i + 6
    b += Sum1(g) + Ch(g, h, a) + K[t] + this.X[t];
    f = Long.fromNumber(f + b).getLowBitsUnsigned();
    b += Sum0(c) + Maj(c, d, e);
    ++t;

    // t = 8 * i + 7
    a += Sum1(f) + Ch(f, g, h) + K[t] + this.X[t];
    e = Long.fromNumber(e + a).getLowBitsUnsigned();
    a += Sum0(b) + Maj(b, c, d);
    ++t;
  }

  this.H1 += a;
  this.H2 += b;
  this.H3 += c;
  this.H4 += d;
  this.H5 += e;
  this.H6 += f;
  this.H7 += g;
  this.H8 += h;

  //
  // reset the offset and clean out the word buffer.
  //
  this.xOff = 0;
  for(var i = 0; i < 16; i++) {
    this.X[i] = 0;
  }
}

/* SHA-256 functions */
var Ch = function(x, y, z) {
  return (x & y) ^ ((~x) & z);
}

var Maj = function(x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

var Sum0 = function(x) {
  return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^ ((x >>> 22) | (x << 10));
}

var Sum1 = function(x) {
  return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^ ((x >>> 25) | (x << 7));
}

var Theta0 = function(x) {
  return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
}

var Theta1 = function(x) {
  return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
}

/* SHA-256 Constants
 * (represent the first 32 bits of the fractional parts of the
 * cube roots of the first sixty-four prime numbers)
 */
var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];