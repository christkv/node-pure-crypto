var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 20;
const BYTE_LENGTH = 64;

var RIPEMD160 = exports.RIPEMD160 = function() {
  // Call base class constructor
  BaseDigest.call(this);
    
  // RIPEMD160 variables
  this.xOff = 0;
  this.X = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  
  // Reset 
  this.reset();
}

inherits(RIPEMD160, BaseDigest);

RIPEMD160.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

RIPEMD160.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

RIPEMD160.prototype.processWord = function(src, inOff) {
  this.X[this.xOff++] = (src[inOff] & 0xff) | ((src[inOff + 1] & 0xff) << 8)
      | ((src[inOff + 2] & 0xff) << 16) | ((src[inOff + 3] & 0xff) << 24); 

  if (this.xOff == 16) {
    this.processBlock();
  }  
}

RIPEMD160.prototype.processBlock = function() {
  var self = this;

  var a = aa = this.H0;
  var b = bb = this.H1;
  var c = cc = this.H2;
  var d = dd = this.H3;
  var e = ee = this.H4;

  //
  // Rounds 1 - 16
  //
  // left
  a = util.rotl(a + f1(b,c,d) + this.X[ 0], 11) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f1(a,b,c) + this.X[ 1], 14) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f1(e,a,b) + this.X[ 2], 15) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f1(d,e,a) + this.X[ 3], 12) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f1(c,d,e) + this.X[ 4],  5) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f1(b,c,d) + this.X[ 5],  8) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f1(a,b,c) + this.X[ 6],  7) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f1(e,a,b) + this.X[ 7],  9) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f1(d,e,a) + this.X[ 8], 11) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f1(c,d,e) + this.X[ 9], 13) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f1(b,c,d) + this.X[10], 14) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f1(a,b,c) + this.X[11], 15) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f1(e,a,b) + this.X[12],  6) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f1(d,e,a) + this.X[13],  7) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f1(c,d,e) + this.X[14],  9) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f1(b,c,d) + this.X[15],  8) + e; c = util.rotl(c, 10);

  // right
  aa = util.rotl(aa + f5(bb,cc,dd) + this.X[ 5] + 0x50a28be6,  8) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f5(aa,bb,cc) + this.X[14] + 0x50a28be6,  9) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f5(ee,aa,bb) + this.X[ 7] + 0x50a28be6,  9) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f5(dd,ee,aa) + this.X[ 0] + 0x50a28be6, 11) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f5(cc,dd,ee) + this.X[ 9] + 0x50a28be6, 13) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f5(bb,cc,dd) + this.X[ 2] + 0x50a28be6, 15) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f5(aa,bb,cc) + this.X[11] + 0x50a28be6, 15) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f5(ee,aa,bb) + this.X[ 4] + 0x50a28be6,  5) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f5(dd,ee,aa) + this.X[13] + 0x50a28be6,  7) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f5(cc,dd,ee) + this.X[ 6] + 0x50a28be6,  7) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f5(bb,cc,dd) + this.X[15] + 0x50a28be6,  8) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f5(aa,bb,cc) + this.X[ 8] + 0x50a28be6, 11) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f5(ee,aa,bb) + this.X[ 1] + 0x50a28be6, 14) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f5(dd,ee,aa) + this.X[10] + 0x50a28be6, 14) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f5(cc,dd,ee) + this.X[ 3] + 0x50a28be6, 12) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f5(bb,cc,dd) + this.X[12] + 0x50a28be6,  6) + ee; cc = util.rotl(cc, 10);

  //
  // Rounds 16-31
  //
  // left
  e = util.rotl(e + f2(a,b,c) + this.X[ 7] + 0x5a827999,  7) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f2(e,a,b) + this.X[ 4] + 0x5a827999,  6) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f2(d,e,a) + this.X[13] + 0x5a827999,  8) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f2(c,d,e) + this.X[ 1] + 0x5a827999, 13) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f2(b,c,d) + this.X[10] + 0x5a827999, 11) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f2(a,b,c) + this.X[ 6] + 0x5a827999,  9) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f2(e,a,b) + this.X[15] + 0x5a827999,  7) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f2(d,e,a) + this.X[ 3] + 0x5a827999, 15) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f2(c,d,e) + this.X[12] + 0x5a827999,  7) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f2(b,c,d) + this.X[ 0] + 0x5a827999, 12) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f2(a,b,c) + this.X[ 9] + 0x5a827999, 15) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f2(e,a,b) + this.X[ 5] + 0x5a827999,  9) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f2(d,e,a) + this.X[ 2] + 0x5a827999, 11) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f2(c,d,e) + this.X[14] + 0x5a827999,  7) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f2(b,c,d) + this.X[11] + 0x5a827999, 13) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f2(a,b,c) + this.X[ 8] + 0x5a827999, 12) + d; b = util.rotl(b, 10);

  // right
  ee = util.rotl(ee + f4(aa,bb,cc) + this.X[ 6] + 0x5c4dd124,  9) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f4(ee,aa,bb) + this.X[11] + 0x5c4dd124, 13) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f4(dd,ee,aa) + this.X[ 3] + 0x5c4dd124, 15) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f4(cc,dd,ee) + this.X[ 7] + 0x5c4dd124,  7) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f4(bb,cc,dd) + this.X[ 0] + 0x5c4dd124, 12) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f4(aa,bb,cc) + this.X[13] + 0x5c4dd124,  8) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f4(ee,aa,bb) + this.X[ 5] + 0x5c4dd124,  9) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f4(dd,ee,aa) + this.X[10] + 0x5c4dd124, 11) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f4(cc,dd,ee) + this.X[14] + 0x5c4dd124,  7) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f4(bb,cc,dd) + this.X[15] + 0x5c4dd124,  7) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f4(aa,bb,cc) + this.X[ 8] + 0x5c4dd124, 12) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f4(ee,aa,bb) + this.X[12] + 0x5c4dd124,  7) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f4(dd,ee,aa) + this.X[ 4] + 0x5c4dd124,  6) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f4(cc,dd,ee) + this.X[ 9] + 0x5c4dd124, 15) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f4(bb,cc,dd) + this.X[ 1] + 0x5c4dd124, 13) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f4(aa,bb,cc) + this.X[ 2] + 0x5c4dd124, 11) + dd; bb = util.rotl(bb, 10);

  //
  // Rounds 32-47
  //
  // left
  d = util.rotl(d + f3(e,a,b) + this.X[ 3] + 0x6ed9eba1, 11) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f3(d,e,a) + this.X[10] + 0x6ed9eba1, 13) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f3(c,d,e) + this.X[14] + 0x6ed9eba1,  6) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f3(b,c,d) + this.X[ 4] + 0x6ed9eba1,  7) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f3(a,b,c) + this.X[ 9] + 0x6ed9eba1, 14) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f3(e,a,b) + this.X[15] + 0x6ed9eba1,  9) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f3(d,e,a) + this.X[ 8] + 0x6ed9eba1, 13) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f3(c,d,e) + this.X[ 1] + 0x6ed9eba1, 15) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f3(b,c,d) + this.X[ 2] + 0x6ed9eba1, 14) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f3(a,b,c) + this.X[ 7] + 0x6ed9eba1,  8) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f3(e,a,b) + this.X[ 0] + 0x6ed9eba1, 13) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f3(d,e,a) + this.X[ 6] + 0x6ed9eba1,  6) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f3(c,d,e) + this.X[13] + 0x6ed9eba1,  5) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f3(b,c,d) + this.X[11] + 0x6ed9eba1, 12) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f3(a,b,c) + this.X[ 5] + 0x6ed9eba1,  7) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f3(e,a,b) + this.X[12] + 0x6ed9eba1,  5) + c; a = util.rotl(a, 10);

  // right
  dd = util.rotl(dd + f3(ee,aa,bb) + this.X[15] + 0x6d703ef3,  9) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f3(dd,ee,aa) + this.X[ 5] + 0x6d703ef3,  7) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f3(cc,dd,ee) + this.X[ 1] + 0x6d703ef3, 15) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f3(bb,cc,dd) + this.X[ 3] + 0x6d703ef3, 11) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f3(aa,bb,cc) + this.X[ 7] + 0x6d703ef3,  8) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f3(ee,aa,bb) + this.X[14] + 0x6d703ef3,  6) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f3(dd,ee,aa) + this.X[ 6] + 0x6d703ef3,  6) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f3(cc,dd,ee) + this.X[ 9] + 0x6d703ef3, 14) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f3(bb,cc,dd) + this.X[11] + 0x6d703ef3, 12) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f3(aa,bb,cc) + this.X[ 8] + 0x6d703ef3, 13) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f3(ee,aa,bb) + this.X[12] + 0x6d703ef3,  5) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f3(dd,ee,aa) + this.X[ 2] + 0x6d703ef3, 14) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f3(cc,dd,ee) + this.X[10] + 0x6d703ef3, 13) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f3(bb,cc,dd) + this.X[ 0] + 0x6d703ef3, 13) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f3(aa,bb,cc) + this.X[ 4] + 0x6d703ef3,  7) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f3(ee,aa,bb) + this.X[13] + 0x6d703ef3,  5) + cc; aa = util.rotl(aa, 10);

  //
  // Rounds 48-63
  //
  // left
  c = util.rotl(c + f4(d,e,a) + this.X[ 1] + 0x8f1bbcdc, 11) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f4(c,d,e) + this.X[ 9] + 0x8f1bbcdc, 12) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f4(b,c,d) + this.X[11] + 0x8f1bbcdc, 14) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f4(a,b,c) + this.X[10] + 0x8f1bbcdc, 15) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f4(e,a,b) + this.X[ 0] + 0x8f1bbcdc, 14) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f4(d,e,a) + this.X[ 8] + 0x8f1bbcdc, 15) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f4(c,d,e) + this.X[12] + 0x8f1bbcdc,  9) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f4(b,c,d) + this.X[ 4] + 0x8f1bbcdc,  8) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f4(a,b,c) + this.X[13] + 0x8f1bbcdc,  9) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f4(e,a,b) + this.X[ 3] + 0x8f1bbcdc, 14) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f4(d,e,a) + this.X[ 7] + 0x8f1bbcdc,  5) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f4(c,d,e) + this.X[15] + 0x8f1bbcdc,  6) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f4(b,c,d) + this.X[14] + 0x8f1bbcdc,  8) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f4(a,b,c) + this.X[ 5] + 0x8f1bbcdc,  6) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f4(e,a,b) + this.X[ 6] + 0x8f1bbcdc,  5) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f4(d,e,a) + this.X[ 2] + 0x8f1bbcdc, 12) + b; e = util.rotl(e, 10);

  // right
  cc = util.rotl(cc + f2(dd,ee,aa) + this.X[ 8] + 0x7a6d76e9, 15) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f2(cc,dd,ee) + this.X[ 6] + 0x7a6d76e9,  5) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f2(bb,cc,dd) + this.X[ 4] + 0x7a6d76e9,  8) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f2(aa,bb,cc) + this.X[ 1] + 0x7a6d76e9, 11) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f2(ee,aa,bb) + this.X[ 3] + 0x7a6d76e9, 14) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f2(dd,ee,aa) + this.X[11] + 0x7a6d76e9, 14) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f2(cc,dd,ee) + this.X[15] + 0x7a6d76e9,  6) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f2(bb,cc,dd) + this.X[ 0] + 0x7a6d76e9, 14) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f2(aa,bb,cc) + this.X[ 5] + 0x7a6d76e9,  6) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f2(ee,aa,bb) + this.X[12] + 0x7a6d76e9,  9) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f2(dd,ee,aa) + this.X[ 2] + 0x7a6d76e9, 12) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f2(cc,dd,ee) + this.X[13] + 0x7a6d76e9,  9) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f2(bb,cc,dd) + this.X[ 9] + 0x7a6d76e9, 12) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f2(aa,bb,cc) + this.X[ 7] + 0x7a6d76e9,  5) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f2(ee,aa,bb) + this.X[10] + 0x7a6d76e9, 15) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f2(dd,ee,aa) + this.X[14] + 0x7a6d76e9,  8) + bb; ee = util.rotl(ee, 10);

  //
  // Rounds 64-79
  //
  // left
  b = util.rotl(b + f5(c,d,e) + this.X[ 4] + 0xa953fd4e,  9) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f5(b,c,d) + this.X[ 0] + 0xa953fd4e, 15) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f5(a,b,c) + this.X[ 5] + 0xa953fd4e,  5) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f5(e,a,b) + this.X[ 9] + 0xa953fd4e, 11) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f5(d,e,a) + this.X[ 7] + 0xa953fd4e,  6) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f5(c,d,e) + this.X[12] + 0xa953fd4e,  8) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f5(b,c,d) + this.X[ 2] + 0xa953fd4e, 13) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f5(a,b,c) + this.X[10] + 0xa953fd4e, 12) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f5(e,a,b) + this.X[14] + 0xa953fd4e,  5) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f5(d,e,a) + this.X[ 1] + 0xa953fd4e, 12) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f5(c,d,e) + this.X[ 3] + 0xa953fd4e, 13) + a; d = util.rotl(d, 10);
  a = util.rotl(a + f5(b,c,d) + this.X[ 8] + 0xa953fd4e, 14) + e; c = util.rotl(c, 10);
  e = util.rotl(e + f5(a,b,c) + this.X[11] + 0xa953fd4e, 11) + d; b = util.rotl(b, 10);
  d = util.rotl(d + f5(e,a,b) + this.X[ 6] + 0xa953fd4e,  8) + c; a = util.rotl(a, 10);
  c = util.rotl(c + f5(d,e,a) + this.X[15] + 0xa953fd4e,  5) + b; e = util.rotl(e, 10);
  b = util.rotl(b + f5(c,d,e) + this.X[13] + 0xa953fd4e,  6) + a; d = util.rotl(d, 10);

  // right
  bb = util.rotl(bb + f1(cc,dd,ee) + this.X[12],  8) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f1(bb,cc,dd) + this.X[15],  5) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f1(aa,bb,cc) + this.X[10], 12) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f1(ee,aa,bb) + this.X[ 4],  9) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f1(dd,ee,aa) + this.X[ 1], 12) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f1(cc,dd,ee) + this.X[ 5],  5) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f1(bb,cc,dd) + this.X[ 8], 14) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f1(aa,bb,cc) + this.X[ 7],  6) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f1(ee,aa,bb) + this.X[ 6],  8) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f1(dd,ee,aa) + this.X[ 2], 13) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f1(cc,dd,ee) + this.X[13],  6) + aa; dd = util.rotl(dd, 10);
  aa = util.rotl(aa + f1(bb,cc,dd) + this.X[14],  5) + ee; cc = util.rotl(cc, 10);
  ee = util.rotl(ee + f1(aa,bb,cc) + this.X[ 0], 15) + dd; bb = util.rotl(bb, 10);
  dd = util.rotl(dd + f1(ee,aa,bb) + this.X[ 3], 13) + cc; aa = util.rotl(aa, 10);
  cc = util.rotl(cc + f1(dd,ee,aa) + this.X[ 9], 11) + bb; ee = util.rotl(ee, 10);
  bb = util.rotl(bb + f1(cc,dd,ee) + this.X[11], 11) + aa; dd = util.rotl(dd, 10);

  dd += c + this.H1;
  this.H1 = this.H2 + d + ee;
  this.H2 = this.H3 + e + aa;
  this.H3 = this.H4 + a + bb;
  this.H4 = this.H0 + b + cc;
  this.H0 = dd;

  //
  // reset the offset and clean out the word buffer.
  //
  this.xOff = 0;
  for(var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }
}

/*
 * f1,f2,f3,f4 are the basic RIPEMD160 functions.
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

var f5 = function(x, y, z) {
  return x ^ (y | ~z);
}

RIPEMD160.prototype.getAlgorithmName = function() {
  return "RIPEMD160";
}

//
// Common to all digests
RIPEMD160.prototype.reset = function() {
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
  this.H4 = 0xc3d2e1f0;
  
  this.xOff = 0;
  
  for (var i = 0; i != this.X.length; i++) {
    this.X[i] = 0;
  }  
}

RIPEMD160.prototype.processLength = function(bitLength) {
  if (this.xOff > 14) {
    this.processBlock();
  }

  this.X[14] = bitLength.getLowBitsUnsigned();
  this.X[15] = bitLength.shiftRightUnsigned(32).getLowBitsUnsigned();
}

//
// Common to all digests
RIPEMD160.prototype.doFinal = function(output, index) {
  this.finish();
  index = index == null ? 0 : index;
  // Encode the hash
  util.inPlaceEncodeUInt32R(this.H0, output, index + 0);
  util.inPlaceEncodeUInt32R(this.H1, output, index + 4);
  util.inPlaceEncodeUInt32R(this.H2, output, index + 8);
  util.inPlaceEncodeUInt32R(this.H3, output, index + 12);
  util.inPlaceEncodeUInt32R(this.H4, output, index + 16);  
  this.reset();  
  // Return based on encoding
  return DIGEST_LENGTH;
}

