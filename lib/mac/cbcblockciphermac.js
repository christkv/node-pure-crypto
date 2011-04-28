var NullPad = require('padding/null').NullPad,
  CBCMode = require('block/cbc').CBCMode,
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

var CBCBlockCipherMac = exports.CBCBlockCipherMac = function(cipher, macSizeInBits, padding) {
  if(macSizeInBits == null) {
    macSizeInBits = (cipher.getBlockSize() * 8) / 2;
    this.macSize = (macSizeInBits) / 8;
  } else {
    this.macSize = macSizeInBits / 8;      
  }
  // Save padding
  this.padding = padding;
  
  // Checks
  if((macSizeInBits % 8) != 0) {
    throw "MAC size must be multiple of 8";
  }
  
  this.cipher = new CBCMode(cipher, new NullPad());
  this.mac = zeroedArray(cipher.getBlockSize());
  this.buf = zeroedArray(cipher.getBlockSize());
  this.bufOff = 0;
}

CBCBlockCipherMac.prototype.getMacSize = function() {
  return this.macSize;
}

CBCBlockCipherMac.prototype.update = function(src) {
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

CBCBlockCipherMac.prototype.digest = function() {
  var blockSize = this.cipher.getBlockSize();
  
  if(this.padding == null) {
    // Pad with zeros
    while(this.bufOff < blockSize) {
      this.buf[this.bufOff] = 0;
      this.bufOff++;
    }
  } else {
    if(this.bufOff == blockSize) {
      this.mac = this.cipher.processBlock(true, this.buf, 0, this.mac, 0, this.buf.length);
      this.bufOff = 0;
    }
    
    this.buf = this.padding.pad(this.buf);
  }
  
  this.mac = this.cipher.processBlock(true, this.buf, 0, this.mac, 0, this.buf.length);
  this.mac = this.mac.slice(0, this.macSize);

  this.reset();
  return this.mac;
}

CBCBlockCipherMac.prototype.reset = function() {
  // clean the buffer.
  for (var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }

  this.bufOff = 0;
  // reset the underlying cipher.
  this.cipher.reset();
}



