var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const BYTE_LENGTH = 64;
const DIGEST_LENGTH_BYTES = 512 / 8;
const ROUNDS = 10;
const REDUCTION_POLYNOMIAL = 0x011d; // 2^8 + 2^4 + 2^3 + 2 + 1;
const BITCOUNT_ARRAY_SIZE = 32;
// Increment array
const EIGHT = new Array(BITCOUNT_ARRAY_SIZE);
for(var i = 0; i < EIGHT.length; i++) EIGHT[i] = 0;
EIGHT[BITCOUNT_ARRAY_SIZE - 1] = 8;

var Whirlpool = exports.Whirlpool = function() {
  // Buffer information
  this._buffer = new Array(64);
  this._bufferPos = 0;
  this._bitCount = new Array(BITCOUNT_ARRAY_SIZE);
  
  // Internal hash state
  this._hash = new Array(8);
  this._K = new Array(8);
  this._L = new Array(8);
  this._block = new Array(8);
  this._state = new Array(8);
    
  // States
  this.C0 = new Array(256);
  this.C1 = new Array(256);
  this.C2 = new Array(256);
  this.C3 = new Array(256);
  this.C4 = new Array(256);
  this.C5 = new Array(256);
  this.C6 = new Array(256);
  this.C7 = new Array(256);
  this._rc = new Array(ROUNDS + 1);
  
  for(var i = 0; i < 256; i++) {
    // debug("=======================================================")
    var v1 = SBOX[i];
    var v2 = maskWithReductionPolynomial(v1 << 1);
    var v4 = maskWithReductionPolynomial(v2 << 1);
    var v5 = v4 ^ v1;
    var v8 = maskWithReductionPolynomial(v4 << 1);
    var v9 = v8 ^ v1;
    
    // debug("v1 = " + v1)
    // debug("v2 = " + v2)
    // debug("v4 = " + v4)
    // debug("v5 = " + v5)
    // debug("v8 = " + v8)
    // debug("v9 = " + v9)
    
    this.C0[i] = packIntoLong(v1, v1, v4, v1, v8, v5, v2, v9);
    this.C1[i] = packIntoLong(v9, v1, v1, v4, v1, v8, v5, v2);
    this.C2[i] = packIntoLong(v2, v9, v1, v1, v4, v1, v8, v5);
    this.C3[i] = packIntoLong(v5, v2, v9, v1, v1, v4, v1, v8);
    this.C4[i] = packIntoLong(v8, v5, v2, v9, v1, v1, v4, v1);
    this.C5[i] = packIntoLong(v1, v8, v5, v2, v9, v1, v1, v4);
    this.C6[i] = packIntoLong(v4, v1, v8, v5, v2, v9, v1, v1);
    this.C7[i] = packIntoLong(v1, v4, v1, v8, v5, v2, v9, v1);
    // debug("C0[" + i + "] = " + this.C0[i])//.toString(16))
    // debug("C1[" + i + "] = " + this.C1[i])//.toString(16))
    // debug("C2[" + i + "] = " + this.C2[i])//.toString(16))
    // debug("C3[" + i + "] = " + this.C3[i])//.toString(16))
    // debug("C4[" + i + "] = " + this.C4[i])//.toString(16))
    // debug("C5[" + i + "] = " + this.C5[i])//.toString(16))
    // debug("C6[" + i + "] = " + this.C6[i])//.toString(16))
    // debug("C7[" + i + "] = " + this.C7[i])//.toString(16))
  }

  // debug("==============================================================")
  this._rc[0] = Long.ZERO;
  for(var r = 1; r <= ROUNDS; r++) {
    var i = 8 * (r - 1);
    this._rc[r] = this.C0[i].and(m0)
      .xor(this.C1[i + 1].and(m1))
      .xor(this.C2[i + 2].and(m2))
      .xor(this.C3[i + 3].and(m3))
      .xor(this.C4[i + 4].and(m4))
      .xor(this.C5[i + 5].and(m5))
      .xor(this.C6[i + 6].and(m6))
      .xor(this.C7[i + 7].and(m7));
    // debug("_rc[" + i + "] = " + this._rc[r])
  }  
  
  // Reset counters
  this.reset();
}

const m0 = Long.fromString("ff00000000000000", 16);
const m1 = Long.fromString("00ff000000000000", 16);
const m2 = Long.fromString("0000ff0000000000", 16);
const m3 = Long.fromString("000000ff00000000", 16);
const m4 = Long.fromString("00000000ff000000", 16);
const m5 = Long.fromString("0000000000ff0000", 16);
const m6 = Long.fromString("000000000000ff00", 16);
const m7 = Long.fromString("00000000000000ff", 16);

var packIntoLong = function(b7, b6, b5, b4, b3, b2, b1, b0) {
  // Long.fromBits(util.decodeUInt32(src, inOff + 4), util.decodeUInt32(src, inOff + 0));
  return Long.fromBits(util.decodeUInt32R([b0, b1, b2, b3], 0), util.decodeUInt32R([b4, b5, b6, b7], 0));
}


// int's are used to prevent sign extension.  The values that are really being used are
// actually just 0..255
var maskWithReductionPolynomial = function(input) {
  var rv = input;
  if (rv >= 0x100) { // high bit set
    rv ^= REDUCTION_POLYNOMIAL; // reduced by the polynomial
  }
  return rv;
}


Whirlpool.prototype.digestSize = function() {
  return DIGEST_LENGTH;
}

//
// Common to all digests
var update = function(instance, b) {
  instance._buffer[instance._bufferPos] = b;
  instance._bufferPos++;
  
  if(instance._bufferPos == instance._buffer.length) {
    processFilledBuffer(instance, instance._buffer, 0);
  }
  
  increment(instance);
}

var increment = function(self) {
  // debug("------------------------------------------------------- increment");
  // debug(EIGHT)
  var carry = 0;
  for (var i = self._bitCount.length - 1; i >= 0; i--) {
    var sum = (self._bitCount[i] & 0xff) + EIGHT[i] + carry;

    carry = sum >>> 8;
    // if(carry == 1) {
    //   // debug("=============================== carry :: " + carry)
    //   // debug("=============================== sum :: " + sum)      
    // } else {
    //   // debug("=============================== carry :: " + carry)
    //   // debug("=============================== sum :: " + sum)            
    // }
     
    self._bitCount[i] = (sum & 0xff);
    // debug("_bitCount[" + i + "] = " + self._bitCount[i])
  }  
}

//
// Common to all digests
Whirlpool.prototype.update = function(src) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var inOff = 0;
  var len = src.length;
  
  //
  // load in the remainder.
  //
  while(len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;    
  }  
}

var copyBitLength = function(self) {
  var rv = new Array(BITCOUNT_ARRAY_SIZE);
  for (var i = 0; i < rv.length; i++) {
    rv[i] = self._bitCount[i] & 0xff;
  }
  return rv;  
}

// this takes a buffer of information and fills the block
var processFilledBuffer = function(self, src, inOff) {
  // debug("---------------------------------------------------------------------processFilledBuffer")
  // debug("======================================================== _buffer")
  // for(var i = 0; i < self._buffer.length; i++) {
  //   debug("_buffer[" + i + "] = " + self._buffer[i])
  // }  
  
  // copies into the block...
  for(var i = 0; i < self._state.length; i++) {
    self._block[i] = Long.fromBits(util.decodeUInt32(self._buffer, (i * 8) + 4), util.decodeUInt32(self._buffer, (i * 8)));
    // this._block[i] = bytesToLongFromBuffer(_buffer, i * 8);
  }
  // debug("======================================================== _block")
  // for(var i = 0; i < self._block.length; i++) {
  //   debug("_block[" + i + "] = " + self._block[i])
  // }  

  // debug("------------------------------------------------- 1")
  // debug(self._K)
  
  processBlock(self);
  self._bufferPos = 0;
  for(var i = 0; i < self._buffer.length; i++) self._buffer[i] = 0;
}

var processBlock = function(self) {
  // debug("-------------------------------------------------------------PROCESSBLOCK")
  // buffer contents have been transferred to the _block[] array via
  // processFilledBuffer
  // debug("======================================================== K")
  // for(var i = 0; i < self._K.length; i++) {
  //   debug("_K[i] = " + self._K[i])
  // }
  // 
  // debug("======================================================== _hash")
  // for(var i = 0; i < self._hash.length; i++) {
  //   debug("_hash[i] = " + self._hash[i])
  // }
  // 
  // debug("======================================================== _state")
  // for(var i = 0; i < self._state.length; i++) {
  //   debug("_state[i] = " + self._state[i])
  // }
  // 
  // debug("======================================================== _block")
  // for(var i = 0; i < self._block.length; i++) {
  //   debug("_block[i] = " + self._block[i])
  // }  
  // 
  // debug("======================================================== _L")
  // for(var i = 0; i < self._L.length; i++) {
  //   debug("_L[i] = " + self._L[i])
  // }  
  
  // compute and apply K^0
  for (var i = 0; i < 8; i++) {
    self._K[i] = self._hash[i];
    self._state[i] = self._block[i].xor(self._K[i]);
  }

  // iterate over the rounds
  for (var round = 1; round <= ROUNDS; round++) {
    for (var i = 0; i < 8; i++)
    {
      self._L[i] = Long.ZERO;
      // _L[i] ^= C0[(int)(_K[(i - 0) & 7] >>> 56) & 0xff];
      self._L[i] = self._L[i].xor(self.C0[self._K[(i - 0) & 7].shiftRightUnsigned(56).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C1[(int)(_K[(i - 1) & 7] >>> 48) & 0xff];
      self._L[i] = self._L[i].xor(self.C1[self._K[(i - 1) & 7].shiftRightUnsigned(48).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C2[(int)(_K[(i - 2) & 7] >>> 40) & 0xff];
      self._L[i] = self._L[i].xor(self.C2[self._K[(i - 2) & 7].shiftRightUnsigned(40).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C3[(int)(_K[(i - 3) & 7] >>> 32) & 0xff];
      self._L[i] = self._L[i].xor(self.C3[self._K[(i - 3) & 7].shiftRightUnsigned(32).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C4[(int)(_K[(i - 4) & 7] >>> 24) & 0xff];
      self._L[i] = self._L[i].xor(self.C4[self._K[(i - 4) & 7].shiftRightUnsigned(24).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C5[(int)(_K[(i - 5) & 7] >>> 16) & 0xff];
      self._L[i] = self._L[i].xor(self.C5[self._K[(i - 5) & 7].shiftRightUnsigned(16).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C6[(int)(_K[(i - 6) & 7] >>>  8) & 0xff];
      self._L[i] = self._L[i].xor(self.C6[self._K[(i - 6) & 7].shiftRightUnsigned(8).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C7[(int)(_K[(i - 7) & 7]) & 0xff];
      self._L[i] = self._L[i].xor(self.C7[self._K[(i - 7) & 7].getLowBitsUnsigned() & 0xff]);
    }

    self._K = self._L.slice(0, self._K.length)
    
    // _K[0] ^= _rc[round];
    self._K[0] = self._K[0].xor(self._rc[round]);
    
    // apply the round transformation
    for (var i = 0; i < 8; i++) {
      // _L[i] = _K[i];
      self._L[i] = self._K[i];
      
      // _L[i] ^= C0[(int)(_state[(i - 0) & 7] >>> 56) & 0xff];
      self._L[i] = self._L[i].xor(self.C0[self._state[(i - 0) & 7].shiftRightUnsigned(56).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C1[(int)(_state[(i - 1) & 7] >>> 48) & 0xff];
      self._L[i] = self._L[i].xor(self.C1[self._state[(i - 1) & 7].shiftRightUnsigned(48).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C2[(int)(_state[(i - 2) & 7] >>> 40) & 0xff];
      self._L[i] = self._L[i].xor(self.C2[self._state[(i - 2) & 7].shiftRightUnsigned(40).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C3[(int)(_state[(i - 3) & 7] >>> 32) & 0xff];
      self._L[i] = self._L[i].xor(self.C3[self._state[(i - 3) & 7].shiftRightUnsigned(32).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C4[(int)(_state[(i - 4) & 7] >>> 24) & 0xff];
      self._L[i] = self._L[i].xor(self.C4[self._state[(i - 4) & 7].shiftRightUnsigned(24).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C5[(int)(_state[(i - 5) & 7] >>> 16) & 0xff];
      self._L[i] = self._L[i].xor(self.C5[self._state[(i - 5) & 7].shiftRightUnsigned(16).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C6[(int)(_state[(i - 6) & 7] >>> 8) & 0xff];
      self._L[i] = self._L[i].xor(self.C6[self._state[(i - 6) & 7].shiftRightUnsigned(8).getLowBitsUnsigned() & 0xff]);
      // _L[i] ^= C7[(int)(_state[(i - 7) & 7]) & 0xff];
      self._L[i] = self._L[i].xor(self.C7[self._state[(i - 7) & 7].getLowBitsUnsigned() & 0xff]);
    }
    
    // save the current state
    self._state = self._L.slice(0, self._state.length);
  }
  
  // apply Miuaguchi-Preneel compression
  for (var i = 0; i < 8; i++) {
    // _hash[i] ^= _state[i] ^ _block[i];
    self._hash[i] = self._hash[i].xor(self._state[i].xor(self._block[i]));
  }  
}

Whirlpool.prototype.finish = function() {
  /*
   * this makes a copy of the current bit length. at the expense of an
   * object creation of 32 bytes rather than providing a _stopCounting
   * boolean which was the alternative I could think of.
   */
  var bitLength = copyBitLength(this);   
  this._buffer[this._bufferPos++] |= 0x80;

  if (this._bufferPos == this._buffer.length) {
    processFilledBuffer(this, _buffer, 0);
  }
  
  /*
   * Final block contains 
   * [ ... data .... ][0][0][0][ length ]
   * 
   * if [ length ] cannot fit.  Need to create a new block.
   */
  if (this._bufferPos > 32) {
    while(this._bufferPos != 0) {
      update(this, 0);
    }
  }
  
  while (this._bufferPos <= 32) {
    update(this, 0);
  }

  var self = this;
  // debug("--------------------------------------------------------DIGEST")
  // buffer contents have been transferred to the _block[] array via
  // processFilledBuffer
  // debug("======================================================== K")
  // for(var i = 0; i < self._K.length; i++) {
  //   debug("_K[i] = " + self._K[i])
  // }
  // 
  // debug("======================================================== _hash")
  // for(var i = 0; i < self._hash.length; i++) {
  //   debug("_hash[i] = " + self._hash[i])
  // }
  // 
  // debug("======================================================== _state")
  // for(var i = 0; i < self._state.length; i++) {
  //   debug("_state[i] = " + self._state[i])
  // }
  // 
  // debug("======================================================== _block")
  // for(var i = 0; i < self._block.length; i++) {
  //   debug("_block[i] = " + self._block[i])
  // }  
  // 
  // debug("======================================================== _L")
  // for(var i = 0; i < self._L.length; i++) {
  //   debug("_L[i] = " + self._L[i])
  // }  
  // 
  // debug("======================================================== bitLength")
  // for(var i = 0; i < bitLength.length; i++) {
  //   debug("bitLength[i] = " + bitLength[i])
  // }  
  
  // copy the length information to the final 32 bytes of the
  // 64 byte block....
  util.copy(this._buffer, 32, bitLength, 0, 32);

  // debug("======================================================== _L")
  // for(var i = 0; i < self._buffer.length; i++) {
  //   debug("_buffer[" + i + "] = " + self._buffer[i])
  // }  

  processFilledBuffer(this, this._buffer, 0);
}

//
// Common to all digests
Whirlpool.prototype.reset = function() {
  for(var i = 0; i < this._bitCount.length; i++) this._bitCount[i] = 0;
  for(var i = 0; i < this._buffer.length; i++) this._buffer[i] = Long.ZERO;
  for(var i = 0; i < this._hash.length; i++) this._hash[i] = Long.ZERO;
  for(var i = 0; i < this._K.length; i++) this._K[i] = Long.ZERO;
  for(var i = 0; i < this._L.length; i++) this._L[i] = Long.ZERO;
  for(var i = 0; i < this._block.length; i++) this._block[i] = Long.ZERO;
  for(var i = 0; i < this._state.length; i++) this._state[i] = Long.ZERO;
}

Whirlpool.prototype.processLength = function(bitLength) {
  this.x[7] = bitLength;
}

//
// Common to all digests
Whirlpool.prototype.digest = function(encoding) {
  this.finish();

  var output = new Array(DIGEST_LENGTH_BYTES);
  for(var i = 0; i < 8; i++) {
    util.inPlaceEncodeUInt32(this._hash[i].getHighBits(), output, (i * 8));    
    util.inPlaceEncodeUInt32(this._hash[i].getLowBits(), output, (i * 8) + 4);
  }
  
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

const SBOX = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
];


