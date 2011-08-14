var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var startsWith = function(self, str, index) {
  index = index == null ? 0 : index;
  return self.substring(index, str.length) === str;
}

var Buffered = exports.Buffered = function(cipher, bitBlockSize) {
  if(cipher != null) {
    this.cipher = cipher;
    this.buf = zeroedData(this.blockSize);
    this.bufOff = 0;
    
    // Check if we can handle partial blocks on doFinal.
    var name = cipher.getAlgorithmName();    
    var idx = name.indexOf('/') + 1;
    this.pgpCFB = (idx > 0 && startsWith(name, "PGP"), idx);
    
    if(this.pgpCFB) {
      this.partialBlockOkay = true;
    } else {
      partialBlockOkay = (idx > 0 && (startsWith(name, "CFB", idx) || startsWith(name, "OFB", idx) || startsWith(name, "OpenPGP", idx) || startsWith(name, "SIC", idx) || startsWith(name, "GCTR", idx)));
    }
  }
}

Buffered.prototype.getUnderlyingCipher = function() {
  return this.cipher;
}

Buffered.prototype.init = function(forEncryption, withIv, iv) {
  var args = Array.prototype.slice.call(arguments, 2);
  // Set encrypting
  this.forEncryption = forEncryption; 
  // Reset cipher
  this.reset();

  // Check what kind of cipher we have
  var name = this.cipher.getAlgorithmName();    
  var idx = name.indexOf('/');
  
  // If we have modes powered cipher
  if(idx != -1) {
    this.cipher.init.apply(this.cipher, [forEncryption, withIv].concat(args));        
  } else {
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [forEncryption].concat(args));    
  }
}

Buffered.prototype.getBlockSize = function() {
  return this.blockSize;
}

Buffered.prototype.getUpdateOutputSize = function() {
  var total = len + this.bufOff;
  var leftOver;

  if(this.pgpCFB) {
    leftOver = total % this.buf.length - (this.cipher.getBlockSize() + 2);
  } else {
    leftOver = total % this.buf.length;
  }

  return total - leftOver;  
}

Buffered.prototype.getOutputSize = function(length) {
  return length + this.bufOff;
}

Buffered.prototype.processByte = function(input, out, outOff) {
  var resultLen = 0;
  this.buf[this.bufOff++] = input;

  if(this.bufOff == this.buf.length) {
    resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
    this.bufOff = 0;
  }

  return resultLen;
}

Buffered.prototype.processBytes = function(input, inOff, len, out, outOff) {
  if(len < 0) {
    throw new Error("Can't have a negative input length!");
  }

  var blockSize = this.getBlockSize();
  var length = this.getUpdateOutputSize(len);
  
  if(length > 0) {
    if ((outOff + length) > out.length) {
      throw new Error("output buffer too short");
    }
  }

  var resultLen = 0;
  var gapLen = this.buf.length - this.bufOff;

  if(len > gapLen) {
    util.copy(this.buf, this.bufOff, input, inOff, gapLen);
    resultLen += this.cipher.processBlock(this.buf, 0, out, outOff);

    this.bufOff = 0;
    len -= gapLen;
    inOff += gapLen;

    while (len > this.buf.length) {
      resultLen += this.cipher.processBlock(input, inOff, out, outOff + resultLen);
      len -= blockSize;
      inOff += blockSize;
    }
  }

  util.copy(this.buf, this.bufOff, input, inOff, len);
  this.bufOff += len;

  if(this.bufOff == this.buf.length) {
    resultLen += this.cipher.processBlock(this.buf, 0, out, outOff + resultLen);
    this.bufOff = 0;
  }

  return resultLen;
}

Buffered.prototype.doFinal = function(out, outOff) {
  try {
    var resultLen = 0;

    if(outOff + this.bufOff > out.length) throw new Error("output buffer too short for doFinal()");
    if(this.bufOff != 0) {
      if (!this.partialBlockOkay) {
        throw new Error("data not block size aligned");
      }

      this.cipher.processBlock(this.buf, 0, this.buf, 0);
      resultLen = this.bufOff;
      this.bufOff = 0;
      util.copy(out, outOff, this.buf, 0, resultLen);
    }

    return resultLen;
  } catch(err) {
    // Reset cipher
    reset();
    // Rethrow error
    throw err;
  }
}

Buffered.prototype.reset = function() {
  //
  // clean the buffer.
  //
  for(var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }

  this.bufOff = 0;

  //
  // reset the underlying cipher.
  //
  this.cipher.reset();
}

















