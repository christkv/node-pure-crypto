var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Gost28147 = require('symmetric/block/gost28147').Gost28147,
  Long = require('long').Long;

const DIGEST_LENGTH = 32;
const BYTE_LENGTH = 32;

var GOST3411 = exports.GOST3411 = function() {
  // Set up arrays
  this.S = util.zeroedArray(32);
  this.U = util.zeroedArray(32);
  this.V = util.zeroedArray(32);
  this.W = util.zeroedArray(32);

  this.K = util.zeroedArray(32);

  this.H = util.zeroedArray(32);
  this.L = util.zeroedArray(32);
  this.M = util.zeroedArray(32);
  this.Sum = util.zeroedArray(32);
  this.C = [util.zeroedArray(32), util.zeroedArray(32), util.zeroedArray(32), util.zeroedArray(32)];

  this.a = util.zeroedArray(8);
  this.wS = util.zeroedArray(16);
  this.w_S = util.zeroedArray(16);
  
  this.xBuf = util.zeroedArray(32);
  this.xBufOff = 0;
  this.byteCount = Long.ZERO;
  // Set up sbox
  this.sBox = Gost28147.DSbox_A;
  this.cipher = new Gost28147();
  this.cipher.init(true, null, this.sBox);
  // Reset state
  this.reset();
}

GOST3411.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

GOST3411.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

//A (x) = (x0 ^ x1) || x3 || x2 || x1
var A  = function(self, src) {
  for(var j = 0; j < 8; j++) {
    self.a[j] = src[j] ^ src[j + 8];
  }

  util.copy(src, 0, src, 8, 24);
  util.copy(src, 24, self.a, 0, 8);
  return src;
}

var P = function(self, src) {
  for(var k = 0; k < 8; k++) {
    self.K[4*k] = src[k];
    self.K[1 + 4*k] = src[ 8 + k];
    self.K[2 + 4*k] = src[16 + k];
    self.K[3 + 4*k] = src[24 + k];
  }

  return self.K;  
}

var E = function(self, key, s, sOff, src, inOff) {
  self.cipher.workingKey = self.cipher.generateWorkingKey(key);
  self.cipher.processBlock(src, inOff);
  util.copy(s, sOff, src, inOff, self.cipher.getBlockSize());
  return s;
}

var fw = function(self, src) {
  cpyBytesToShort(src, self.wS);
  self.w_S[15] = self.wS[0] ^ self.wS[1] ^ self.wS[2] ^ self.wS[3] ^ self.wS[12] ^ self.wS[15];
  util.copy(self.w_S, 0, self.wS, 1, 15);
  cpyShortToBytes(self.w_S, src);
}

var cpyBytesToShort = function(S, wS) {
  for(var i = 0; i < S.length/2; i++) {
    wS[i] = (((S[i*2+1]<<8)&0xFF00)|(S[i*2]&0xFF));
  }
}

var cpyShortToBytes = function(wS, S) {
  for(var i = 0; i < S.length/2; i++) {
    S[i*2 + 1] = (wS[i] >> 8) & 0xff;
    S[i*2] = wS[i] & 0xff;
  }
}

GOST3411.prototype.processBlock = function(src, inOff) {
  this.M = src.slice(inOff, inOff + 32);
  //key step 1
  // H = h3 || h2 || h1 || h0
  // S = s3 || s2 || s1 || s0
  this.U = this.H.slice(0, 32);
  this.V = this.M.slice(0, 32);
  
  for(var j = 0; j < 32; j++) {
    this.W[j] = this.U[j] ^ this.V[j];
  }

  // Encrypt gost28147-ECB
  this.S = E(this, P(this, this.W), this.S, 0, this.H.slice(0), 0); // s0 = EK0 [h0]

  //keys step 2,3,4
  for (var i = 1; i < 4; i++) {
    var tmpA = A(this, this.U);
    for(var j = 0; j < 32; j++) {
      this.U[j] = tmpA[j] ^ this.C[i][j];
    }
    
    this.V = A(this, A(this, this.V));

    for(var j = 0; j < 32; j++) {
      this.W[j] = this.U[j] ^ this.V[j];
    }
    
    // Encrypt gost28147-ECB
    this.S = E(this, P(this, this.W), this.S, i * 8, this.H.slice(0), i * 8); // si = EKi [hi]
  }

  // x(M, H) = y61(H^y(M^y12(S)))
  for(var n = 0; n < 12; n++) {
    fw(this, this.S);
  }
  
  for(var n = 0; n < 32; n++) {
    this.S[n] = this.S[n] ^ this.M[n];
  }
  
  fw(this, this.S);
  
  for(var n = 0; n < 32; n++) {
    this.S[n] = this.H[n] ^ this.S[n];
  }
  
  for(var n = 0; n < 61; n++) {
    fw(this, this.S);
  }
  
  this.H = this.S.slice(0, this.H.length);
}

var update = function(self, byte) {
  self.xBuf[self.xBufOff++] = byte;
  if(self.xBufOff == self.xBuf.length) {
    sumByteArray(self, self.xBuf); // calc sum M
    self.processBlock(self.xBuf, 0);
    self.xBufOff = 0;
  }
  self.byteCount = self.byteCount.add(Long.fromNumber(1));
}

GOST3411.prototype.update = function(src) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var inOff = 0;
  var len = src.length;

  while((this.xBufOff != 0) && (len > 0)) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }

  while(len > this.xBuf.length) {
    this.xBuf = src.slice(inOff, inOff + this.xBuf.length);
    sumByteArray(this, this.xBuf); // calc sum M
    this.processBlock(this.xBuf, 0);
    inOff += this.xBuf.length;
    len -= this.xBuf.length;
    this.byteCount = this.byteCount.add(Long.fromNumber(this.xBuf.length));
  }

  // load in the remainder.
  while (len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }
}


//
// Common to all digests
GOST3411.prototype.reset = function() {
  this.byteCount = Long.ZERO;
  this.xBufOff = 0;
  
  for(var i = 0; i < this.H.length; i++) {
    this.H[i] = 0;
  }

  for(var i = 0; i < this.L.length; i++) {
    this.L[i] = 0;
  }
  
  for(var i = 0; i < this.M.length; i++) {
    this.M[i] = 0;
  }

  for(var i = 0; i < this.C[1].length; i++) {
    this.C[1][i] = 0;
  }
  
  for(var i = 0; i < this.C[3].length; i++) {
    this.C[3][i] = 0;
  }
  
  for(var i = 0; i < this.Sum.length; i++) {
    this.Sum[i] = 0;
  }
  
  for(var i = 0; i < this.xBuf.length; i++) {
    this.xBuf[i] = 0;
  }
  
  this.C[2] = C2.slice(0);
}

GOST3411.prototype.getAlgorithmName = function() {
  return "GOST3411";
}

var finish = function(self) {
  // var lowBits = util.
  var finalByteCount = self.byteCount.multiply(Long.fromNumber(8));
  util.inPlaceEncodeUInt32R(finalByteCount.getLowBits(), self.L, 0);
  util.inPlaceEncodeUInt32R(finalByteCount.getHighBits(), self.L, 4);
  
  while(self.xBufOff != 0) {
    update(self, 0);
  }
  
  // Process blocks
  self.processBlock(self.L, 0);
  self.processBlock(self.Sum, 0);
}

//
// Common to all digests
GOST3411.prototype.doFinal = function(output, index) {
  finish(this);
  // Ensure valid index
  index = index == null ? 0 : index;
  // Copy hash
  for(var i = 0; i < this.H.length; i++) {
    output[index + i] =  this.H[i];
  }
  
  // Reset
  this.reset();
  // Return based on encoding
  return DIGEST_LENGTH;
}

/**
 * reset the chaining variables to the IV values.
 */
const C2 = [
   0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,
   0xFF,0x00,0xFF,0x00,0xFF,0x00,0xFF,0x00,
   0x00,0xFF,0xFF,0x00,0xFF,0x00,0x00,0xFF,
   0xFF,0x00,0x00,0x00,0xFF,0xFF,0x00,0xFF];

//  256 bitsblock modul -> (Sum + a mod (2^256))
var sumByteArray = function(self, src) {
 var carry = 0;

 for(var i = 0; i != self.Sum.length; i++) {
   var sum = (self.Sum[i] & 0xff) + (src[i] & 0xff) + carry;
   self.Sum[i] = sum & 0xff;
   carry = sum >>> 8;
 }
}

