var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

//
// Additive constants
//
const Y1 = 0x5a827999;
const Y2 = 0x6ed9eba1;
const Y3 = 0x8f1bbcdc;
const Y4 = 0xca62c1d6;

const DIGEST_LENGTH = 20;
const BYTE_LENGTH = 64;

var SHA1 = exports.SHA1 = function() {
  // Call base class constructor
  BaseDigest.call(this);
  // Setup SHA1
  this.X = new Array(80);
  // Reset state
  this.reset();
}

inherits(SHA1, BaseDigest);

SHA1.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

SHA1.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

SHA1.prototype.processWord = function(src, inOff) {
  this.X[this.xOff++] = (src[inOff] & 0xff) << 24 | (src[inOff + 1] & 0xff) << 16
              | (src[inOff + 2] & 0xff) << 8 | src[inOff + 3] & 0xff; 

  if (this.xOff == 16) {
    this.processBlock();
  }        
}

SHA1.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }

  this.X[14] = Long.fromNumber(bitLength).shiftRightUnsigned(32).getLowBitsUnsigned();
  this.X[15] = (bitLength & 0xffffffff);
}

//
// Common to all digests
SHA1.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);
  
  this.H1 = 0x67452301;
  this.H2 = 0xefcdab89;
  this.H3 = 0x98badcfe;
  this.H4 = 0x10325476;
  this.H5 = 0xc3d2e1f0;

  this.xOff = 0;
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }
}

//
// Common to all digests
SHA1.prototype.doFinal = function(output, index) {
  // add padding
  this.finish();
  index = index == null ? 0 : index;
  // Ouput digest
  util.inPlaceEncodeUInt32(this.H1, output, index + 0);
  util.inPlaceEncodeUInt32(this.H2, output, index + 4);
  util.inPlaceEncodeUInt32(this.H3, output, index + 8);
  util.inPlaceEncodeUInt32(this.H4, output, index + 12);
  util.inPlaceEncodeUInt32(this.H5, output, index + 16);  
  // Reset
  this.reset();
  // Return based on encoding
  return DIGEST_LENGTH;
}

var f = function(u, v, w) {
  return ((u & v) | ((~u) & w));
}

var h = function(u, v, w) {
  return (u ^ v ^ w);
}

var g = function(u, v, w) {
  return ((u & v) | (u & w) | (v & w));
}

SHA1.prototype.getAlgorithmName = function() {
  return "SHA-1";
}

SHA1.prototype.processBlock = function() {
  //
  // expand 16 word block into 80 word block.
  //
  for(var i = 16; i < 80; i++) {
    var t = this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16];
    this.X[i] = t << 1 | t >>> 31;
  }

  //
  // set up working variables.
  //
  var A = this.H1;
  var B = this.H2;
  var C = this.H3;
  var D = this.H4;
  var E = this.H5;

  //
  // round 1
  //
  var idx = 0;

  for(var j = 0; j < 4; j++) {
    // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
    // B = rotateLeft(B, 30)
    E += (A << 5 | A >>> 27) + f(B, C, D) + this.X[idx++] + Y1;
    B = B << 30 | B >>> 2;

    D += (E << 5 | E >>> 27) + f(A, B, C) + this.X[idx++] + Y1;
    A = A << 30 | A >>> 2;

    C += (D << 5 | D >>> 27) + f(E, A, B) + this.X[idx++] + Y1;
    E = E << 30 | E >>> 2;

    B += (C << 5 | C >>> 27) + f(D, E, A) + this.X[idx++] + Y1;
    D = D << 30 | D >>> 2;

    A += (B << 5 | B >>> 27) + f(C, D, E) + this.X[idx++] + Y1;
    C = C << 30 | C >>> 2;
  }

  //
  // round 2
  //
  for (var j = 0; j < 4; j++) {
    // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
    // B = rotateLeft(B, 30)
    E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y2;
    B = B << 30 | B >>> 2;   
  
    D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y2;
    A = A << 30 | A >>> 2;
  
    C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y2;
    E = E << 30 | E >>> 2;
  
    B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y2;
    D = D << 30 | D >>> 2;

    A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y2;
    C = C << 30 | C >>> 2;
  }

  //
  // round 3
  //
  for (var j = 0; j < 4; j++) {
    // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
    // B = rotateLeft(B, 30)
    E += (A << 5 | A >>> 27) + g(B, C, D) + this.X[idx++] + Y3;
    B = B << 30 | B >>> 2;
  
    D += (E << 5 | E >>> 27) + g(A, B, C) + this.X[idx++] + Y3;
    A = A << 30 | A >>> 2;
  
    C += (D << 5 | D >>> 27) + g(E, A, B) + this.X[idx++] + Y3;
    E = E << 30 | E >>> 2;
  
    B += (C << 5 | C >>> 27) + g(D, E, A) + this.X[idx++] + Y3;
    D = D << 30 | D >>> 2;

    A += (B << 5 | B >>> 27) + g(C, D, E) + this.X[idx++] + Y3;
    C = C << 30 | C >>> 2;
  }

  //
  // round 4
  //
  for (var j = 0; j <= 3; j++) {
    // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
    // B = rotateLeft(B, 30)
    E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y4;
    B = B << 30 | B >>> 2;
  
    D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y4;
    A = A << 30 | A >>> 2;
  
    C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y4;
    E = E << 30 | E >>> 2;
  
    B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y4;
    D = D << 30 | D >>> 2;

    A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y4;
    C = C << 30 | C >>> 2;
  }

  this.H1 += A;
  this.H2 += B;
  this.H3 += C;
  this.H4 += D;
  this.H5 += E;
  
  //
  // reset start of the buffer.
  //
  this.xOff = 0;
  for(var i = 0; i < 16; i++) {
    this.X[i] = 0;
  }
}


