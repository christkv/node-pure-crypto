var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 28;
const BYTE_LENGTH = 64;

var SHA224 = exports.SHA224 = function() {
  // Call base class constructor
  BaseDigest.call(this);
  // Setup SHA224
  this.X = new Array(64);
  // Reset state
  this.reset();
}

inherits(SHA224, BaseDigest);

SHA224.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

SHA224.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

SHA224.prototype.getAlgorithmName = function() {
  return "SHA-224";
}

SHA224.prototype.processWord = function(src, inOff) {
  var n = src[inOff] << 24;
      n |= (src[++inOff] & 0xff) << 16;
      n |= (src[++inOff] & 0xff) << 8;
      n |= (src[++inOff] & 0xff);
  this.X[this.xOff] = n;
  
  if (++this.xOff == 16) {
    this.processBlock();
  }
}

SHA224.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }
  
  this.X[14] = Long.fromNumber(bitLength).shiftRightUnsigned(32).getLowBitsUnsigned();
  this.X[15] = (bitLength & 0xffffffff);
}

//
// Common to all digests
SHA224.prototype.reset = function() {
  // General reset
  BaseDigest.prototype.reset.call(this);
  
  // SHA-224 initial hash value
  this.H1 = 0xc1059ed8;
  this.H2 = 0x367cd507;
  this.H3 = 0x3070dd17;
  this.H4 = 0xf70e5939;
  this.H5 = 0xffc00b31;
  this.H6 = 0x68581511;
  this.H7 = 0x64f98fa7;
  this.H8 = 0xbefa4fa4;

  this.xOff = 0;
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }
}

//
// Common to all digests
SHA224.prototype.doFinal = function(output, index) {
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
  // Reset
  this.reset();
  // Return based on encoding
  return DIGEST_LENGTH;
}

SHA224.prototype.processBlock = function() {
  //
  // expand 16 word block into 64 word blocks.
  //
  for (var t = 16; t <= 63; t++) {
    // debug("=================================================================")
    // debug("Theta1(this.X[t - 2]) = " + Long.fromNumber(Theta1(this.X[t - 2])).getLowBitsUnsigned().toString(16));
    // debug("this.X[t - 7] = " + Long.fromNumber(this.X[t - 7]).getLowBitsUnsigned().toString(16));
    // debug("Theta0(this.X[t - 15]) = " + Long.fromNumber(Theta0(this.X[t - 15])).getLowBitsUnsigned().toString(16));
    // debug("this.X[t - 16] = " + Long.fromNumber(this.X[t - 16]).getLowBitsUnsigned().toString(16));
    
    this.X[t] = Theta1(this.X[t - 2]) + this.X[t - 7] + Theta0(this.X[t - 15]) + this.X[t - 16];
    // debug("this.X[t] = " + Long.fromNumber(this.X[t]).getLowBitsUnsigned().toString(16));
  }
  
  // debug("--------------------------------------------------------------------")

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
  
  // debug("================================================================= before")
  // debug("H1 = " + Long.fromNumber(this.H1).getLowBitsUnsigned().toString(16));
  // debug("H2 = " + Long.fromNumber(this.H2).getLowBitsUnsigned().toString(16));
  // debug("H3 = " + Long.fromNumber(this.H3).getLowBitsUnsigned().toString(16));
  // debug("H4 = " + Long.fromNumber(this.H4).getLowBitsUnsigned().toString(16));
  // debug("H5 = " + Long.fromNumber(this.H5).getLowBitsUnsigned().toString(16));
  // debug("H6 = " + Long.fromNumber(this.H6).getLowBitsUnsigned().toString(16));
  // debug("H7 = " + Long.fromNumber(this.H7).getLowBitsUnsigned().toString(16));
  // debug("H8 = " + Long.fromNumber(this.H8).getLowBitsUnsigned().toString(16));
  
  // debug("================================================================= X")
  // for(var i = 0; i < this.X.length; i++) {
  //   debug("X[" + i + "] = " + Long.fromNumber(this.X[i]).getLowBitsUnsigned().toString(16));
  // }
  // debug(this.X)

  var t = 0;
  for(var i = 0; i < 8; i ++) {
    // debug("  ========================================================================= ROUND " + i)
    // t = 8 * i
    h += Sum1(e) + Ch(e, f, g) + K[t] + this.X[t];
    // d += h;
    d = Long.fromNumber(d + h).getLowBitsUnsigned();
    h += Sum0(a) + Maj(a, b, c);
    ++t;
    
    // debug("  ================================================================= 0")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 1
    g += Sum1(d) + Ch(d, e, f) + K[t] + this.X[t];
    // c += g;
    c = Long.fromNumber(c + g).getLowBitsUnsigned();
    g += Sum0(h) + Maj(h, a, b);
    ++t;

    // debug("  ================================================================= 1")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 2
    f += Sum1(c) + Ch(c, d, e) + K[t] + this.X[t];
    // b += f;
    b = Long.fromNumber(b + f).getLowBitsUnsigned();
    f += Sum0(g) + Maj(g, h, a);
    ++t;

    // debug("  ================================================================= 2")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 3
    e += Sum1(b) + Ch(b, c, d) + K[t] + this.X[t];
    // a += e;
    a = Long.fromNumber(a + e).getLowBitsUnsigned();
    e += Sum0(f) + Maj(f, g, h);
    ++t;

    // debug("  ================================================================= 3")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 4
    d += Sum1(a) + Ch(a, b, c) + K[t] + this.X[t];
    // h += d;
    // h = Long.fromNumber(h).add(d).getLowBitsUnsigned();
    h = Long.fromNumber(h + d).getLowBitsUnsigned();
    d += Sum0(e) + Maj(e, f, g);
    ++t;

    // debug("  ================================================================= 4")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 5
    c += Sum1(h) + Ch(h, a, b) + K[t] + this.X[t];
    // g += c;
    g = Long.fromNumber(g + c).getLowBitsUnsigned();
    c += Sum0(d) + Maj(d, e, f);
    ++t;

    // debug("  ================================================================= 5")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 6
    b += Sum1(g) + Ch(g, h, a) + K[t] + this.X[t];
    // f += b;
    f = Long.fromNumber(f + b).getLowBitsUnsigned();
    b += Sum0(c) + Maj(c, d, e);
    ++t;

    // debug("  ================================================================= 6")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));        

    // t = 8 * i + 7
    a += Sum1(f) + Ch(f, g, h) + K[t] + this.X[t];
    // e += a;
    e = Long.fromNumber(e + a).getLowBitsUnsigned();
    a += Sum0(b) + Maj(b, c, d);
    ++t;

    // debug("  ================================================================= 7")
    // debug("  a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
    // debug("  b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
    // debug("  c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
    // debug("  d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
    // debug("  e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
    // debug("  f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
    // debug("  g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
    // debug("  h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));            
  }

  // debug("================================================================= after 0")
  // debug("a = " + Long.fromNumber(a).getLowBitsUnsigned().toString(16));
  // debug("b = " + Long.fromNumber(b).getLowBitsUnsigned().toString(16));
  // debug("c = " + Long.fromNumber(c).getLowBitsUnsigned().toString(16));
  // debug("d = " + Long.fromNumber(d).getLowBitsUnsigned().toString(16));
  // debug("e = " + Long.fromNumber(e).getLowBitsUnsigned().toString(16));
  // debug("f = " + Long.fromNumber(f).getLowBitsUnsigned().toString(16));
  // debug("g = " + Long.fromNumber(g).getLowBitsUnsigned().toString(16));
  // debug("h = " + Long.fromNumber(h).getLowBitsUnsigned().toString(16));

  this.H1 += a;
  this.H2 += b;
  this.H3 += c;
  this.H4 += d;
  this.H5 += e;
  this.H6 += f;
  this.H7 += g;
  this.H8 += h;

  // debug("================================================================= after")
  // debug("H1 = " + Long.fromNumber(this.H1).getLowBitsUnsigned().toString(16));
  // debug("H2 = " + Long.fromNumber(this.H2).getLowBitsUnsigned().toString(16));
  // debug("H3 = " + Long.fromNumber(this.H3).getLowBitsUnsigned().toString(16));
  // debug("H4 = " + Long.fromNumber(this.H4).getLowBitsUnsigned().toString(16));
  // debug("H5 = " + Long.fromNumber(this.H5).getLowBitsUnsigned().toString(16));
  // debug("H6 = " + Long.fromNumber(this.H6).getLowBitsUnsigned().toString(16));
  // debug("H7 = " + Long.fromNumber(this.H7).getLowBitsUnsigned().toString(16));
  // debug("H8 = " + Long.fromNumber(this.H8).getLowBitsUnsigned().toString(16));

  //
  // reset the offset and clean out the word buffer.
  //
  this.xOff = 0;
  for(var i = 0; i < 16; i++) {
    this.X[i] = 0;
  }
}

/* SHA-224 functions */
var Ch = function(x, y, z) {
  return ((x & y) ^ ((~x) & z));
}

var Maj = function(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z));
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


/* SHA-224 Constants
 * (represent the first 32 bits of the fractional parts of the
 * cube roots of the first sixty-four prime numbers)
 */
var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// var f = function(u, v, w) {
//   return ((u & v) | ((~u) & w));
// }
// 
// var h = function(u, v, w) {
//   return (u ^ v ^ w);
// }
// 
// var g = function(u, v, w) {
//   return ((u & v) | (u & w) | (v & w));
// }
// 
// SHA224.prototype.processBlock = function() {
//   // debug("==================================================== X")
//   // debug(this.X)
//   //
//   // expand 16 word block into 80 word block.
//   //
//   for(var i = 16; i < 80; i++) {
//     // debug("  this.X[i - 3] = " + this.X[i - 3])
//     // debug("  this.X[i - 3] = " + Long.fromNumber(this.X[i - 3]).getLowBitsUnsigned().toString(16))
//     // debug("  this.X[i - 8] = " + Long.fromNumber(this.X[i - 8]).getLowBitsUnsigned().toString(16))
//     // debug("  this.X[i - 14] = " + Long.fromNumber(this.X[i - 14]).getLowBitsUnsigned().toString(16))
//     // debug("  this.X[i - 16] = " + Long.fromNumber(this.X[i - 16]).getLowBitsUnsigned().toString(16))
//     var t = this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16];
//     // debug("==================================================== X")
//     // debug(this.X)
//     
//     // var t = Long.fromNumber(this.X[i - 3]).xor(Long.fromNumber(this.X[i - 8])).xor(Long.fromNumber(this.X[i - 14])).xor(Long.fromNumber(this.X[i - 16])).getLowBitsUnsigned();
//     
//     // debug("  t = " + Long.fromNumber(t).getLowBitsUnsigned().toString(16))
//     // debug("  t = " + Long.fromNumber(t).getLowBitsUnsigned().toString(16))
//     this.X[i] = t << 1 | t >>> 31;
//     // this.X[i] = util.rotl(t, 1) | util.rotr(t, 31);
//     // this.X[i] = util.rotl(this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16], 1);
//     // debug("  this.X[i] = " + Long.fromNumber(this.X[i]).getLowBitsUnsigned().toString(16))
//   }
// 
//   // debug("==================================================== X")
//   // debug(this.X)
//   // debug("=============================================== before")
//   // debug("H1 = " + Long.fromNumber(this.H1).getLowBitsUnsigned().toString(16))
//   // debug("H2 = " + Long.fromNumber(this.H2).getLowBitsUnsigned().toString(16))
//   // debug("H3 = " + Long.fromNumber(this.H3).getLowBitsUnsigned().toString(16))
//   // debug("H4 = " + Long.fromNumber(this.H4).getLowBitsUnsigned().toString(16))
//   // debug("H5 = " + Long.fromNumber(this.H5).getLowBitsUnsigned().toString(16))
// 
//   //
//   // set up working variables.
//   //
//   var A = this.H1;
//   var B = this.H2;
//   var C = this.H3;
//   var D = this.H4;
//   var E = this.H5;
// 
//   //
//   // round 1
//   //
//   var idx = 0;
// 
//   for(var j = 0; j < 4; j++) {
//     // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
//     // B = rotateLeft(B, 30)
//     E += (A << 5 | A >>> 27) + f(B, C, D) + this.X[idx++] + Y1;
//     B = B << 30 | B >>> 2;
// 
//     D += (E << 5 | E >>> 27) + f(A, B, C) + this.X[idx++] + Y1;
//     A = A << 30 | A >>> 2;
// 
//     C += (D << 5 | D >>> 27) + f(E, A, B) + this.X[idx++] + Y1;
//     E = E << 30 | E >>> 2;
// 
//     B += (C << 5 | C >>> 27) + f(D, E, A) + this.X[idx++] + Y1;
//     D = D << 30 | D >>> 2;
// 
//     A += (B << 5 | B >>> 27) + f(C, D, E) + this.X[idx++] + Y1;
//     C = C << 30 | C >>> 2;
//   }
// 
//   //
//   // round 2
//   //
//   for (var j = 0; j < 4; j++) {
//     // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
//     // B = rotateLeft(B, 30)
//     E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y2;
//     B = B << 30 | B >>> 2;   
//   
//     D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y2;
//     A = A << 30 | A >>> 2;
//   
//     C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y2;
//     E = E << 30 | E >>> 2;
//   
//     B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y2;
//     D = D << 30 | D >>> 2;
// 
//     A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y2;
//     C = C << 30 | C >>> 2;
//   }
// 
//   //
//   // round 3
//   //
//   for (var j = 0; j < 4; j++) {
//     // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
//     // B = rotateLeft(B, 30)
//     E += (A << 5 | A >>> 27) + g(B, C, D) + this.X[idx++] + Y3;
//     B = B << 30 | B >>> 2;
//   
//     D += (E << 5 | E >>> 27) + g(A, B, C) + this.X[idx++] + Y3;
//     A = A << 30 | A >>> 2;
//   
//     C += (D << 5 | D >>> 27) + g(E, A, B) + this.X[idx++] + Y3;
//     E = E << 30 | E >>> 2;
//   
//     B += (C << 5 | C >>> 27) + g(D, E, A) + this.X[idx++] + Y3;
//     D = D << 30 | D >>> 2;
// 
//     A += (B << 5 | B >>> 27) + g(C, D, E) + this.X[idx++] + Y3;
//     C = C << 30 | C >>> 2;
//   }
// 
//   //
//   // round 4
//   //
//   for (var j = 0; j <= 3; j++) {
//     // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
//     // B = rotateLeft(B, 30)
//     E += (A << 5 | A >>> 27) + h(B, C, D) + this.X[idx++] + Y4;
//     B = B << 30 | B >>> 2;
//   
//     D += (E << 5 | E >>> 27) + h(A, B, C) + this.X[idx++] + Y4;
//     A = A << 30 | A >>> 2;
//   
//     C += (D << 5 | D >>> 27) + h(E, A, B) + this.X[idx++] + Y4;
//     E = E << 30 | E >>> 2;
//   
//     B += (C << 5 | C >>> 27) + h(D, E, A) + this.X[idx++] + Y4;
//     D = D << 30 | D >>> 2;
// 
//     A += (B << 5 | B >>> 27) + h(C, D, E) + this.X[idx++] + Y4;
//     C = C << 30 | C >>> 2;
//   }
// 
//   this.H1 += A;
//   this.H2 += B;
//   this.H3 += C;
//   this.H4 += D;
//   this.H5 += E;
//   
//   // debug("=============================================== after")
//   // debug("H1 = " + Long.fromNumber(this.H1).getLowBitsUnsigned().toString(16))
//   // debug("H2 = " + Long.fromNumber(this.H2).getLowBitsUnsigned().toString(16))
//   // debug("H3 = " + Long.fromNumber(this.H3).getLowBitsUnsigned().toString(16))
//   // debug("H4 = " + Long.fromNumber(this.H4).getLowBitsUnsigned().toString(16))
//   // debug("H5 = " + Long.fromNumber(this.H5).getLowBitsUnsigned().toString(16))
// 
//   //
//   // reset start of the buffer.
//   //
//   this.xOff = 0;
//   for(var i = 0; i < 16; i++) {
//     this.X[i] = 0;
//   }
// }


