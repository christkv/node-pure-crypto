var NullPad = require('symmetric/padding/null').NullPad,
  CBCMode = require('symmetric/block/cbc').CBCMode,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

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

var CFBBlockCipherMac = exports.CFBBlockCipherMac = function(cipher, iv, cfbBitSize, macSizeInBits, padding) {
  // Initialize only if we have a cipher
  if(cipher != null) {
    if(macSizeInBits == null) {
      macSizeInBits = (cipher.getBlockSize() * 8) / 2;
      this.macSize = (macSizeInBits) / 8;
    } else {
      this.macSize = macSizeInBits / 8;      
    }

    if(cfbBitSize == null) {
      cfbBitSize = 8;
    }
    // Save padding
    this.padding = padding;

    // Checks
    if((macSizeInBits % 8) != 0) {
      throw "MAC size must be multiple of 8";
    }

    this.cipher = new MacCFBBlockCipher(cipher, cfbBitSize, iv);
    this.mac = zeroedArray(this.cipher.getBlockSize());
    this.buf = zeroedArray(this.cipher.getBlockSize());  
    this.bufOff = 0;    
  }
}

CFBBlockCipherMac.prototype.init = function() {
  // Get all the arguments
  var args = Array.prototype.slice.call(arguments, 0);
  // Append the arguments to the cipher initializer
  this.cipher.init.apply(this.cipher, [true].concat(args));
}

CFBBlockCipherMac.prototype.getMacSize = function() {
  return this.macSize;
}

CFBBlockCipherMac.prototype.update = function(src) {
  if(src.length < 0) throw "Can't have a negative input length!";
  
  var inOff = 0;
  var len = src.length;
  var blockSize = this.cipher.getBlockSize();
  var gapLen = blockSize - this.bufOff;

  if(len > gapLen) {
    util.copy(this.buf, this.bufOff, src, inOff, gapLen);
    this.mac = this.cipher.processBlock(true, this.buf, this.bufOff, this.mac, 0, this.buf.length);

    this.bufOff = 0;
    len = len - gapLen;
    inOff = inOff + gapLen;
    
    while(len > blockSize) {
      this.mac = this.cipher.processBlock(true, src, inOff, this.mac, 0, this.mac.length);
      len = len - blockSize;
      inOff = inOff + blockSize;
    }    
  }  

  util.copy(this.buf, this.bufOff, src, inOff, len);
  this.bufOff = this.bufOff + len;
}

CFBBlockCipherMac.prototype.digest = function() {
  var blockSize = this.cipher.getBlockSize();
  
  if(this.padding == null) {
    // Pad with zeros
    while(this.bufOff < blockSize) {
      this.buf[this.bufOff] = 0;
      this.bufOff++;
    }
  } else {
    this.buf = this.padding.pad(this.buf);
  }
  
  this.mac = this.cipher.processBlock(true, this.buf, 0, this.mac, 0, this.buf.length);
  this.mac = this.cipher.getMacBlock();
  this.mac = this.mac.slice(0, this.macSize);
  this.reset();
  return this.mac;
}

CFBBlockCipherMac.prototype.reset = function() {
  // clean the buffer.
  for (var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }

  this.bufOff = 0;
  // reset the underlying cipher.
  this.cipher.reset();
}

var MacCFBBlockCipher = function(cipher, bitBlockSize, iv) {
  this.cipher = cipher;
  this.blockSize = bitBlockSize / 8;
  this.iv = iv != null ? iv : zeroedArray(cipher.getBlockSize());
  this.cfbV = zeroedArray(cipher.getBlockSize());
  this.cfbOutV = zeroedArray(cipher.getBlockSize());
  
  if(iv.length < this.iv.length) {
    util.copy(this.iv, (this.iv.length - iv.length), iv, 0, iv.length);
  } else {
    util.copy(this.iv, 0, iv, 0, this.iv.length);
  }

  this.reset();  
}

MacCFBBlockCipher.prototype.reset = function() {
  util.copy(this.cfbV, 0, this.iv, 0, this.iv.length);
  this.cipher.reset();
}

MacCFBBlockCipher.prototype.getBlockSize = function() {
  return this.blockSize;
}

MacCFBBlockCipher.prototype.processBlock = function(encrypting, src, srcIndex, dest, destIndex, len) {
  if(src == null) return "";
  if(srcIndex == null) srcIndex = 0;  
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  
  // If we specify no destination array use the source ones
  if(dest == null) {
    dest = data; 
    destIndex = srcIndex;
    len = data.length;
  }

  this.cfbOutV = this.cipher.processBlock(this.cfbV.slice(0), 0, encrypting);
  
  //
  // XOR the cfbV with the plaintext producing the cipher text
  //
  for (var i = 0; i < this.blockSize; i++) {
    dest[destIndex + i] = this.cfbOutV[i] ^ src[srcIndex + i];
  }

  util.copy(this.cfbV, 0, this.cfbV, this.blockSize, this.cfbV.length - this.blockSize)
  util.copy(this.cfbV, this.cfbV.length - this.blockSize, dest, destIndex, this.blockSize);
  return dest;
} 

MacCFBBlockCipher.prototype.getMacBlock = function() {
  return this.cipher.processBlock(this.cfbV.slice(0), 0, true);
}