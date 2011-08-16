var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  CBC = require('symmetric/modes/cbc').CBC,
  ISO7816d4Padding = require('padding/iso7816d4padding').ISO7816d4Padding,
  util = require('utils'),
  Long = require('long').Long;

var longZeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = Long.ZERO;
  return a;
}

var zeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

const CONSTANT_128 = 0x87;
const CONSTANT_64 = 0x1b;

var CMac = exports.CMac = function(cipher, macSizeInBits) { 
  if(cipher != null) {
    macSizeInBits = macSizeInBits == null ? cipher.getBlockSize() * 8 : macSizeInBits;  
    if((macSizeInBits % 8) != 0) throw new Error("MAC size must be multiple of 8");
    if(macSizeInBits > (cipher.getBlockSize() * 8)) throw new Error("MAC size must be less or equal to " + (cipher.getBlockSize() * 8));
    if(cipher.getBlockSize() != 8 && cipher.getBlockSize() != 16) throw new Error("Block size must be either 64 or 128 bits");

    // Set up cipher and values
    this.cipher = new CBC(cipher);
    this.macSize = macSizeInBits / 8;
    this.mac = zeroedArray(cipher.getBlockSize());
    this.buf = zeroedArray(cipher.getBlockSize());
    this.ZEROES = zeroedArray(cipher.getBlockSize());
    this.bufOff = 0;    
  }
}

CMac.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName();
}

var doubleLu = function(input) {
  var FirstBit = (input[0] & 0xFF) >> 7;
  var ret = zeroedArray(input.length);
  
  for(var i = 0; i < input.length - 1; i++) {
    ret[i] = ((input[i] << 1) + ((input[i + 1] & 0xFF) >> 7));
  }

  ret[input.length - 1] = (input[input.length - 1] << 1);

  if(FirstBit == 1) {
    ret[input.length - 1] ^= input.length == 16 ? CONSTANT_128 : CONSTANT_64;
  }

  return ret;  
}

CMac.prototype.init = function(key) {
  this.reset();
  
  this.cipher.init(true, false, key);
  
  //initializes the L, Lu, Lu2 numbers
  this.L = zeroedArray(this.ZEROES.length);
  this.cipher.processBlock(this.ZEROES, 0, this.L, 0);
  this.Lu = doubleLu(this.L);
  this.Lu2 = doubleLu(this.Lu);
  
  this.cipher.init(true, false, key);
}

CMac.prototype.getMacSize = function() {
  return macSize;
}

CMac.prototype.update = function(input, inOff, len) {
  if(!Array.isArray(input)) {
    if(this.bufOff == this.buf.length) {
      this.cipher.processBlock(this.buf, 0, this.mac, 0);
      this.bufOff = 0;
    }
    
    this.buf[this.bufOff++] = input;
  } else {
    if(len < 0) throw new Error("Can't have a negative input length!");
    
    var blockSize = this.cipher.getBlockSize();
    var gapLen = blockSize - this.bufOff;
    
    if(len > gapLen) {
      util.copy(this.buf, this.bufOff, input, inOff, gapLen);
      this.cipher.processBlock(this.buf, 0, this.mac, 0);
      
      this.bufOff = 0;
      len -= gapLen;
      inOff += gapLen;
      
      while(len > blockSize) {
        this.cipher.processBlock(input, inOff, this.mac, 0);
        len -= blockSize;
        inOff += blockSize;
      }
    }

    util.copy(this.buf, this.bufOff, input, inOff, len);
    this.bufOff += len;
  }
}

CMac.prototype.doFinal = function(out, outOff) {
  var blockSize = this.cipher.getBlockSize();
  
  var lu = null;
  if(this.bufOff == blockSize) {
    lu = this.Lu;
  } else {
    new ISO7816d4Padding().addPadding(this.buf, this.bufOff);
    lu = this.Lu2;
  }
  
  for(var i = 0; i < this.mac.length; i++) {
    this.buf[i] ^= lu[i] & 255;
  }

  this.cipher.processBlock(this.buf, 0, this.mac, 0);
  util.copy(out, outOff, this.mac, 0, this.macSize);
  this.reset();
  return this.macSize;
}

CMac.prototype.reset = function() {
  for(var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }
  
  this.bufOff = 0;
  this.cipher.reset();
}

// const blockLengths = {};
// blockLengths["GOST3411"] = 32;
// blockLengths["MD2"] = 16;
// blockLengths["MD4"] = 64;
// blockLengths["MD5"] = 64;
// 
// blockLengths["RIPEMD128"] = 64;
// blockLengths["RIPEMD160"] = 64;
// 
// blockLengths["SHA-1"] = 64;
// blockLengths["SHA-224"] = 64;
// blockLengths["SHA-256"] = 64;
// blockLengths["SHA-384"] = 128;
// blockLengths["SHA-512"] = 128;
// 
// blockLengths["Tiger"] = 64;
// blockLengths["Whirlpool"] = 64;
// 
// const IPAD = 0x36;
// const OPAD = 0x5c;
// 
// var getByteLength = function(digest) {
//   if(digest["getByteLength"] != null) {
//     return digest.byteLength();
//   } 
//   
//   var b = blockLengths[digest.getAlgorithmName()];
//   if(b == null) throw "unknown digest passed: " + digest.getAlgorithmName();
//   return b;
// }
// 
// var HMac = exports.HMac = function(digest, byteLength) {
//   if(digest != null) {
//     this.digestObject = digest;
//     this.digesSize = digest.getDigestSize();
//     this.blockLength = byteLength != null ? byteLength : getByteLength(digest);
// 
//     this.inputPad = zeroedArray(this.blockLength);
//     this.outputPad = zeroedArray(this.blockLength);
//   }
// }
// 
// HMac.prototype.init = function(key) {
//   // Reset digest
//   this.digestObject.reset();
// 
//   if(key.length > this.blockLength) {
//     this.digestObject.update(key, 0, key.length);
//     this.digestObject.doFinal(this.inputPad, 0);
// 
//     for(var i = this.digestSize; i < this.inputPad.length; i++) {
//       this.inputPad[i] = 0;
//     }
//   } else {
//     util.copy(this.inputPad, 0, key, 0, key.length);
// 
//     for(var i = key.length; i < this.inputPad.length; i++) {
//       this.inputPad[i] = 0;
//     }
//   }
// 
//   this.outputPad = this.inputPad.slice(0);
// 
//   for(var i = 0; i < this.inputPad.length; i++) {
//     this.inputPad[i] = this.inputPad[i] ^ IPAD;
//   }
// 
//   for(var i = 0; i < this.outputPad.length; i++) {
//     this.outputPad[i] = this.outputPad[i] ^ OPAD;
//   }
// 
//   this.digestObject.update(this.inputPad, 0, this.inputPad.length);    
// }
// 
// HMac.prototype.getAlgorithmName = function() {
//   return this.digestObjectSize.getAlgorithmName() + "/HMAC"
// }
// 
// HMac.prototype.getMacSize = function() {
//   return this.digestObjectSize;
// }
// 
// //
// // Common to all digests
// HMac.prototype.update = function(src, inOff, len) {
//   this.digestObject.update(src, inOff, len);
// }
// 
// //
// // Common to all digests
// HMac.prototype.reset = function() {
//   this.digestObject.reset();
//   this.digestObject.update(this.inputPad);
// }
// 
// //
// // Common to all digests
// HMac.prototype.doFinal = function(out, outOff) {
//   var tmp = new Array(this.digestSize);
//   this.digestObject.doFinal(tmp, 0);
//   this.digestObject.update(this.outputPad, 0, this.outputPad.length);
//   this.digestObject.update(tmp, 0, tmp.length);
// 
//   var len = this.digestObject.doFinal(out, outOff);
//   this.reset();
//   return len;
// }
