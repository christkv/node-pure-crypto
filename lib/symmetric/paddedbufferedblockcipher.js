var debug = require('sys').debug,
  inspect = require('sys').inspect,
  inherits = require('util').inherits,  
  util = require('utils'),  
  Buffered = require('symmetric/buffered').Buffered,
  PKCS7Padding = require('padding/pkcs7padding').PKCS7Padding;

var zeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

var PaddedBufferedBlockCipher = exports.PaddedBufferedBlockCipher = function(cipher, padding) {
  this.cipher = cipher;
  this.padding = padding == null ? new PKCS7Padding() : padding;
  this.blockSize = cipher.getBlockSize();
  
  this.buf = zeroedArray(cipher.getBlockSize());
  this.bufOff = 0;
}

inherits(PaddedBufferedBlockCipher, Buffered);

PaddedBufferedBlockCipher.prototype.init = function(forEncryption, key, random) {
  this.forEncryption = forEncryption;

  this.reset();
  
  if(random != null) {
    this.padding.init(random);
    this.cipher.init(forEncryption, key);
  } else {
    this.padding.init();
    this.cipher.init(forEncryption, key);
  }
}

PaddedBufferedBlockCipher.prototype.getOutputSize = function(len) {
  var total = len + this.bufOff;
  var leftOver = total % this.buf.length;
  
  if(leftOver == 0) {
    if(this.forEncryption) return total + this.buf.length;
    return total;
  }
  
  return total - leftOver + this.buf.length;
}

PaddedBufferedBlockCipher.prototype.getUpdateOutputSize = function(len) {
  var total = len + this.bufOff;
  var leftOver = total % this.buf.length;
  
  if(leftOver == 0) return total - this.buf.length;
  return total - leftOver;
}

PaddedBufferedBlockCipher.prototype.processByte = function(input, out, outOff) {
  var resultLen = 0;
  
  if(this.bufOff == this.buf.length) {
    resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
    this.outOff = 0;
  }
  
  this.buf[this.bufOff++] = input;
  return resultLen;
}

PaddedBufferedBlockCipher.prototype.processBytes = function(input, inOff, len, out, outOff) {
  if(len < 0) throw new Error("Can't have a negative input length!");

  var blockSize = this.getBlockSize();
  var length = this.getUpdateOutputSize(len);
  
  if(length > 0) {
    if((outOff + length) > out.length) throw new Error("output buffer too short");
  }
  
  var resultLen = 0;
  var gapLen = this.buf.length - this.bufOff;

  if(len > gapLen) {
    util.copy(this.buf, this.bufOff, input, inOff, gapLen);
    resultLen += this.cipher.processBlock(this.buf, 0, out, outOff);
    
    this.bufOff = 0;
    len -= gapLen;
    inOff += gapLen;
    
    while(len > this.buf.length) {
      resultLen += this.cipher.processBlock(input, inOff, out, outOff + resultLen);
      len -= blockSize;
      inOff += blockSize;
    }
  }
  
  util.copy(this.buf, this.bufOff, input, inOff, len);
  this.bufOff += len;
  return resultLen;
}

PaddedBufferedBlockCipher.prototype.doFinal = function(out, outOff) {
  var blockSize = this.cipher.getBlockSize();
  var resultLen = 0;
  
  if(this.forEncryption) {
    if(this.bufOff == blockSize) {
      if((outOff + 2 * blockSize) > out.length) {
        this.reset();
        
        throw new Error("output buffer too short");
      }
      
      resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
      this.bufOff = 0;
    }
    
    this.padding.addPadding(this.buf, this.bufOff);
    resultLen +=  this.cipher.processBlock(this.buf, 0, out, outOff + resultLen);
    this.reset();
  } else {
    if(this.bufOff == blockSize) {
      resultLen = this.cipher.processBlock(this.buf, 0, this.buf, 0);
      this.bufOff = 0;
    } else {
      this.reset();
      throw new Error("last block incomplete in decryption");
    }
    
    try {
      resultLen -= this.padding.padCount(this.buf);
      util.copy(out, outOff, this.buf, 0, resultLen);
    } catch(err) {}
    
    this.reset();
  }
  
  return resultLen;
}


















