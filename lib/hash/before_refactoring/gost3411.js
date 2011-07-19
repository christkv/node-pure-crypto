var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Gost28147 = require('symmetric/block/gost28147').Gost28147,
  Long = require('long').Long;

const DIGEST_LENGTH = 32;

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
  this.cipher = new Gost28147(null, this.sBox);
  // Reset state
  this.reset();
}

GOST3411.prototype.digestSize = function() {
  return DIGEST_LENGTH;
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
  // debug(self.K)
  // debug(src)
  
  for(var k = 0; k < 8; k++) {
    self.K[4*k] = src[k];
    self.K[1 + 4*k] = src[ 8 + k];
    self.K[2 + 4*k] = src[16 + k];
    self.K[3 + 4*k] = src[24 + k];
  }

  return self.K;  
}

var E = function(self, key, s, sOff, src, inOff) {
  // debug("====================================== key :: " + key)
  // debug("====================================== src :: " + src)
  // debug("====================================== inOff :: " + inOff)
  
  self.cipher.workingKey = self.cipher.generateWorkingKey(key);
  // var a = self.cipher.encrypt(src.slice(inOff, inOff + 8), 0);
  // debug(a)
  // debug("====================================== workingKey :: " + self.cipher.workingKey)
  // debug("====================================== src :: " + src)
  // return a
  var result = self.cipher.encrypt(src, inOff);
  util.copy(s, sOff, src, inOff, self.cipher.getBlockSize());
  return s;
}

var fw = function(self, src) {
  cpyBytesToShort(src, self.wS);
  // debug("      fw-wS-1 :: " + self.wS)
  
  self.w_S[15] = self.wS[0] ^ self.wS[1] ^ self.wS[2] ^ self.wS[3] ^ self.wS[12] ^ self.wS[15];
  // debug("      fw-w_S[15] :: " + self.w_S[15])
  // debug("      fw-wS-2 :: " + self.wS)
  
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

  // debug("---------------------------------------------------- processBlock")

  //key step 1
  // H = h3 || h2 || h1 || h0
  // S = s3 || s2 || s1 || s0
  // System.arraycopy(H, 0, U, 0, 32);
  this.U = this.H.slice(0, 32);
  // debug("  U = " + this.U)
  // System.arraycopy(M, 0, V, 0, 32);
  this.V = this.M.slice(0, 32);
  // debug("  V = " + this.V)
  
  for(var j = 0; j < 32; j++) {
    this.W[j] = this.U[j] ^ this.V[j];
  }
  // debug("  W = " + this.W)

  // Encrypt gost28147-ECB
  this.S = E(this, P(this, this.W), this.S, 0, this.H.slice(0), 0); // s0 = EK0 [h0]

  // debug("  K = " + this.K)
  // debug("  S = " + this.S)

  //keys step 2,3,4
  for (var i = 1; i < 4; i++) {
    var tmpA = A(this, this.U);
    for(var j = 0; j < 32; j++) {
      this.U[j] = tmpA[j] ^ this.C[i][j];
    }
    
    // debug("    U = " + this.U)

    this.V = A(this, A(this, this.V));

    // debug("    V = " + this.V)

    for(var j = 0; j < 32; j++) {
      this.W[j] = this.U[j] ^ this.V[j];
    }
    
    // debug("    W = " + this.W)
  
    // Encrypt gost28147-ECB
    this.S = E(this, P(this, this.W), this.S, i * 8, this.H.slice(0), i * 8); // si = EKi [hi]

    // debug("    S = " + this.S)
  }

  // x(M, H) = y61(H^y(M^y12(S)))
  for(var n = 0; n < 12; n++) {
    fw(this, this.S);
  }
  
  // debug("  S = " + this.S)  

  for(var n = 0; n < 32; n++) {
    this.S[n] = this.S[n] ^ this.M[n];
  }
  
  // debug("  S = " + this.S)  

  fw(this, this.S);
  
  // debug("  S = " + this.S)  
  // debug("  H = " + this.H)  

  for(var n = 0; n < 32; n++) {
    this.S[n] = this.H[n] ^ this.S[n];
  }
  
  // debug("  S = " + this.S)  
  
  for(var n = 0; n < 61; n++) {
    fw(this, this.S);
  }
  
  // debug("  S = " + this.S)
  
  // debug("---------------------- this.H.length = " + this.H.length)
  
  // System.arraycopy(S, 0, H, 0, H.length);
  this.H = this.S.slice(0, this.H.length);
  
  // debug("  H = " + this.H)  
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

GOST3411.prototype.algorithmName = function() {
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
  
  
  
  // Pack.longToLittleEndian(byteCount * 8, L, 0); // get length into L (byteCount * 8 = bitCount)
  // 
  // while (xBufOff != 0)
  // {
  //     update((byte)0);
  // }
  // 
  self.processBlock(self.L, 0);
  self.processBlock(self.Sum, 0);
  
  // processBlock(L, 0);
  // processBlock(Sum, 0);
}

//
// Common to all digests
GOST3411.prototype.digest = function(encoding) {
  // debug(" F ---------------------- this.H.length = " + this.H.length)
  finish(this);
  // debug(" F ---------------------- this.H.length = " + this.H.length)
  
  var output = this.H.slice(0, this.H.length);

  // debug(" F ---------------------- this.H.length = " + this.H.length)
  // debug(" F ---------------------- this.output.length = " + output.length)
  
  // Ouput digest
  // var output = new Array(16);
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

