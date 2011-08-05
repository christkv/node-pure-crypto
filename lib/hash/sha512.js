var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  Long = require('long').Long;

const DIGEST_LENGTH = 64;

var SHA512 = exports.SHA512 = function() {
  // Setup SHA512
  this.W = new Array(80);
  this.xBuf = new Array(8);
  this.xBufOff = 0;
  // Reset state
  this.reset();
}

SHA512.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

SHA512.prototype.getAlgorithmName = function() {
  return "SHA-512";
}

SHA512.prototype.processWord = function(src, inOff) {
  this.W[this.wOff] = Long.fromBits(util.decodeUInt32(src, inOff + 4), util.decodeUInt32(src, inOff + 0));
  if (++this.wOff == 16) {
    this.processBlock();
  }
}

const v1 = Long.fromString("1fffffffffffffff");

/**
 * adjust the byte counts so that byteCount2 represents the
 * upper long (less 3 bits) word of the byte count.
 */
SHA512.prototype.adjustByteCounts = function() {
  if(this.byteCount1.greaterThan(v1)) {
    // byteCount2 += (byteCount1 >>> 61);
    this.byteCount2 = this.byteCount2.add(this.byteCount1.shiftRightUnsigned(61))
    // byteCount1 &= 0x1fffffffffffffffL;
    this.byteCount1 = this.byteCount1.and(v1);
  }
}

SHA512.prototype.processLength = function(lowW, hiW) {
  if (this.wOff > 14) {
    this.processBlock();
  }
  
  this.W[14] = hiW;
  this.W[15] = lowW;
}

SHA512.prototype.processBlock = function() {
  this.adjustByteCounts();
  
  //
  // expand 16 word block into 80 word blocks.
  //
  for(var t = 16; t <= 79; t++) {
    this.W[t] = Sigma1(this.W[t - 2]).add(this.W[t - 7]).add(Sigma0(this.W[t - 15])).add(this.W[t - 16]);
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
  for(var i = 0; i < 10; i ++) {    
    // t = 8 * i
    h = h.add(Sum1(e)).add(Ch(e, f, g)).add(K[t]).add(this.W[t++]);    
    d = d.add(h);
    h = h.add(Sum0(a)).add(Maj(a, b, c));

    // t = 8 * i + 1
    g = g.add(Sum1(d)).add(Ch(d, e, f)).add(K[t]).add(this.W[t++]);
    c = c.add(g);
    g = g.add(Sum0(h)).add(Maj(h, a, b));

    // t = 8 * i + 2
    f = f.add(Sum1(c)).add(Ch(c, d, e)).add(K[t]).add(this.W[t++]);
    b = b.add(f);
    f = f.add(Sum0(g)).add(Maj(g, h, a));

    // t = 8 * i + 3
    e = e.add(Sum1(b)).add(Ch(b, c, d)).add(K[t]).add(this.W[t++]);
    a = a.add(e);
    e = e.add(Sum0(f)).add(Maj(f, g, h));

    // t = 8 * i + 4
    d = d.add(Sum1(a)).add(Ch(a, b, c)).add(K[t]).add(this.W[t++]);
    h = h.add(d);
    d = d.add(Sum0(e)).add(Maj(e, f, g));

    // t = 8 * i + 5
    c = c.add(Sum1(h)).add(Ch(h, a, b)).add(K[t]).add(this.W[t++]);
    g = g.add(c);
    c = c.add(Sum0(d)).add(Maj(d, e, f));

    // t = 8 * i + 6
    b = b.add(Sum1(g)).add(Ch(g, h, a)).add(K[t]).add(this.W[t++]);
    f = f.add(b);
    b = b.add(Sum0(c)).add(Maj(c, d, e));

    // t = 8 * i + 7
    a = a.add(Sum1(f)).add(Ch(f, g, h)).add(K[t]).add(this.W[t++]);
    e = e.add(a);
    a = a.add(Sum0(b)).add(Maj(b, c, d));
  }

  this.H1 = this.H1.add(a);
  this.H2 = this.H2.add(b);
  this.H3 = this.H3.add(c);
  this.H4 = this.H4.add(d);
  this.H5 = this.H5.add(e);
  this.H6 = this.H6.add(f);
  this.H7 = this.H7.add(g);
  this.H8 = this.H8.add(h);

  //
  // reset the offset and clean out the word buffer.
  //
  this.wOff = 0;
  for(var i = 0; i < 16; i++) {
    this.W[i] = Long.ZERO;
  }
}

/* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
var Ch = function(x, y, z) {
  return x.and(y).xor(x.not().and(z));
}

var Maj = function(x, y, z) {
  return x.and(y).xor(x.and(z).xor(y.and(z)));
}

var Sum0 = function(x) {
  var a = x.shiftLeft(36).or(x.shiftRightUnsigned(28));
  var b = x.shiftLeft(30).or(x.shiftRightUnsigned(34));
  var c = x.shiftLeft(25).or(x.shiftRightUnsigned(39));
  return a.xor(b).xor(c);
}

var Sum1 = function(x) {
  return x.shiftLeft(50).or(x.shiftRightUnsigned(14)).xor(x.shiftLeft(46).or(x.shiftRightUnsigned(18))).xor(x.shiftLeft(23).or(x.shiftRightUnsigned(41)));
}

var Sigma0 = function(x) {
  return x.shiftLeft(63).or(x.shiftRightUnsigned(1)).xor(x.shiftLeft(56).or(x.shiftRightUnsigned(8))).xor(x.shiftRightUnsigned(7))
}

var Sigma1 = function(x) {
  return x.shiftLeft(45).or(x.shiftRightUnsigned(19)).xor(x.shiftLeft(3).or(x.shiftRightUnsigned(61))).xor(x.shiftRightUnsigned(6));
}

//
// Common to all digests
var update = function(instance, b) {
  instance.xBuf[instance.xBufOff++] = b;
  
  if(instance.xBufOff === instance.xBuf.length) {
    instance.processWord(instance.xBuf, 0);
    instance.xBufOff = 0;
  }
  
  instance.byteCount1 = instance.byteCount1.add(Long.fromNumber(1));
}

//
// Common to all digests
SHA512.prototype.update = function(src, inOff, len) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var inOff = inOff == null ? 0 : inOff;
  var len = len == null ? src.length :  len;
  
  //
  // fill the current word
  //
  while((this.xBufOff != 0) && (len > 0)) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }
  
  //
  // process whole words.
  //
  while(len > this.xBuf.length) {
    this.processWord(src, inOff);
    
    inOff += this.xBuf.length;
    len -= this.xBuf.length;
    this.byteCount1 = this.byteCount1.add(Long.fromNumber(this.xBuf.length));
  }
  
  //
  // load in the remainder.
  //
  while(len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;    
  }  
}

SHA512.prototype.finish = function() {
  this.adjustByteCounts();
  
  var lowBitLength = this.byteCount1.shiftLeft(3)
  var hiBitLength = this.byteCount2;
  
  //
  // add the pad bytes.
  //
  update(this, 128);
  
  while(this.xBufOff != 0) {
    update(this, 0);
  }
  
  this.processLength(lowBitLength, hiBitLength);
  this.processBlock();
}

//
// Common to all digests
SHA512.prototype.reset = function() {
  // SHA-256 initial hash value
  this.H1 = Long.fromString("6a09e667f3bcc908", 16);
  this.H2 = Long.fromString("bb67ae8584caa73b", 16);
  this.H3 = Long.fromString("3c6ef372fe94f82b", 16);
  this.H4 = Long.fromString("a54ff53a5f1d36f1", 16);
  this.H5 = Long.fromString("510e527fade682d1", 16);
  this.H6 = Long.fromString("9b05688c2b3e6c1f", 16);
  this.H7 = Long.fromString("1f83d9abfb41bd6b", 16);
  this.H8 = Long.fromString("5be0cd19137e2179", 16);

  this.byteCount1 = Long.ZERO;
  this.byteCount2 = Long.ZERO;

  this.xBufOff = 0;  
  for (var i = 0; i != this.xBuf.length; i++) {
    this.xBuf[i] = 0;
  }

  this.wOff = 0;  
  for (var i = 0; i != this.W.length; i++) {
    this.W[i] = Long.ZERO;
  }
}

//
// Common to all digests
SHA512.prototype.doFinal = function(output, index) {
  // add padding
  this.finish();
  index = index == null ? 0 : index;
  // Ouput digest
  util.inPlaceEncodeUInt32(this.H1.getHighBits(), output, index + 0);
  util.inPlaceEncodeUInt32(this.H1.getLowBits(), output, index + 4);
  util.inPlaceEncodeUInt32(this.H2.getHighBits(), output, index + 8);
  util.inPlaceEncodeUInt32(this.H2.getLowBits(), output, index + 12);
  util.inPlaceEncodeUInt32(this.H3.getHighBits(), output, index + 16);
  util.inPlaceEncodeUInt32(this.H3.getLowBits(), output, index + 20);
  util.inPlaceEncodeUInt32(this.H4.getHighBits(), output, index + 24);
  util.inPlaceEncodeUInt32(this.H4.getLowBits(), output, index + 28);
  util.inPlaceEncodeUInt32(this.H5.getHighBits(), output, index + 32);
  util.inPlaceEncodeUInt32(this.H5.getLowBits(), output, index + 36);
  util.inPlaceEncodeUInt32(this.H6.getHighBits(), output, index + 40);
  util.inPlaceEncodeUInt32(this.H6.getLowBits(), output, index + 44);
  util.inPlaceEncodeUInt32(this.H7.getHighBits(), output, index + 48);
  util.inPlaceEncodeUInt32(this.H7.getLowBits(), output, index + 52);
  util.inPlaceEncodeUInt32(this.H8.getHighBits(), output, index + 56);
  util.inPlaceEncodeUInt32(this.H8.getLowBits(), output, index + 60);
  // Reset
  this.reset();
  // Return based on encoding
  return DIGEST_LENGTH;
}

/* SHA-384 and SHA-512 Constants
* (represent the first 64 bits of the fractional parts of the
* cube roots of the first sixty-four prime numbers)
*/
const K = [
  Long.fromString("428a2f98d728ae22", 16), Long.fromString("7137449123ef65cd", 16), Long.fromString("b5c0fbcfec4d3b2f", 16), Long.fromString("e9b5dba58189dbbc", 16),
  Long.fromString("3956c25bf348b538", 16), Long.fromString("59f111f1b605d019", 16), Long.fromString("923f82a4af194f9b", 16), Long.fromString("ab1c5ed5da6d8118", 16),
  Long.fromString("d807aa98a3030242", 16), Long.fromString("12835b0145706fbe", 16), Long.fromString("243185be4ee4b28c", 16), Long.fromString("550c7dc3d5ffb4e2", 16),
  Long.fromString("72be5d74f27b896f", 16), Long.fromString("80deb1fe3b1696b1", 16), Long.fromString("9bdc06a725c71235", 16), Long.fromString("c19bf174cf692694", 16),
  Long.fromString("e49b69c19ef14ad2", 16), Long.fromString("efbe4786384f25e3", 16), Long.fromString("0fc19dc68b8cd5b5", 16), Long.fromString("240ca1cc77ac9c65", 16),
  Long.fromString("2de92c6f592b0275", 16), Long.fromString("4a7484aa6ea6e483", 16), Long.fromString("5cb0a9dcbd41fbd4", 16), Long.fromString("76f988da831153b5", 16),
  Long.fromString("983e5152ee66dfab", 16), Long.fromString("a831c66d2db43210", 16), Long.fromString("b00327c898fb213f", 16), Long.fromString("bf597fc7beef0ee4", 16),
  Long.fromString("c6e00bf33da88fc2", 16), Long.fromString("d5a79147930aa725", 16), Long.fromString("06ca6351e003826f", 16), Long.fromString("142929670a0e6e70", 16),
  Long.fromString("27b70a8546d22ffc", 16), Long.fromString("2e1b21385c26c926", 16), Long.fromString("4d2c6dfc5ac42aed", 16), Long.fromString("53380d139d95b3df", 16),
  Long.fromString("650a73548baf63de", 16), Long.fromString("766a0abb3c77b2a8", 16), Long.fromString("81c2c92e47edaee6", 16), Long.fromString("92722c851482353b", 16),
  Long.fromString("a2bfe8a14cf10364", 16), Long.fromString("a81a664bbc423001", 16), Long.fromString("c24b8b70d0f89791", 16), Long.fromString("c76c51a30654be30", 16),
  Long.fromString("d192e819d6ef5218", 16), Long.fromString("d69906245565a910", 16), Long.fromString("f40e35855771202a", 16), Long.fromString("106aa07032bbd1b8", 16),
  Long.fromString("19a4c116b8d2d0c8", 16), Long.fromString("1e376c085141ab53", 16), Long.fromString("2748774cdf8eeb99", 16), Long.fromString("34b0bcb5e19b48a8", 16),
  Long.fromString("391c0cb3c5c95a63", 16), Long.fromString("4ed8aa4ae3418acb", 16), Long.fromString("5b9cca4f7763e373", 16), Long.fromString("682e6ff3d6b2b8a3", 16),
  Long.fromString("748f82ee5defb2fc", 16), Long.fromString("78a5636f43172f60", 16), Long.fromString("84c87814a1f0ab72", 16), Long.fromString("8cc702081a6439ec", 16),
  Long.fromString("90befffa23631e28", 16), Long.fromString("a4506cebde82bde9", 16), Long.fromString("bef9a3f7b2c67915", 16), Long.fromString("c67178f2e372532b", 16),
  Long.fromString("ca273eceea26619c", 16), Long.fromString("d186b8c721c0c207", 16), Long.fromString("eada7dd6cde0eb1e", 16), Long.fromString("f57d4f7fee6ed178", 16),
  Long.fromString("06f067aa72176fba", 16), Long.fromString("0a637dc5a2c898a6", 16), Long.fromString("113f9804bef90dae", 16), Long.fromString("1b710b35131c471b", 16),
  Long.fromString("28db77f523047d84", 16), Long.fromString("32caab7b40c72493", 16), Long.fromString("3c9ebe0a15c9bebc", 16), Long.fromString("431d67c49c100d4c", 16),
  Long.fromString("4cc5d4becb3e42b6", 16), Long.fromString("597f299cfc657e2a", 16), Long.fromString("5fcb6fab3ad6faec", 16), Long.fromString("6c44198c4a475817", 16)
];
