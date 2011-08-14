var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  inherits = require('sys').inherits,
  Buffered = require('symmetric/buffered').Buffered;

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

var CTS = exports.CTS = function(cipher, bitBlockSize) {
  if(cipher != null) {
    if(cipher.getAlgorithmName().toLowerCase().indexOf('/OFB') != -1 || cipher.getAlgorithmName().toLowerCase().indexOf('/CFB') != -1) {
      throw new Error("CTSBlockCipher can only accept ECB, or CBC ciphers");
    }
    
    this.cipher = cipher;
    this.blockSize = this.cipher.getBlockSize();
    this.buf = zeroedData(this.blockSize * 2);
    this.bufOff = 0;
  }
}

inherits(CTS, Buffered);

CTS.prototype.getUpdateOutputSize = function(len) {
  var total = len + this.bufOff;
  var leftOver = total % this.buf.length;

  if(leftOver == 0) {
    return total - this.buf.length;
  }

  return total - leftOver;
}

CTS.prototype.getOutputSize = function() {
  return len + this.bufOff;
}

CTS.prototype.processByte = function(input, out, outOff) {
  var resultLen = 0;

  if(this.bufOff == this.buf.length) {
    resultLen = this.cipher.processBlock(this.buf, 0, out, outOff);
    util.copy(buf, 0, buf, blockSize, blockSize);
    this.bufOff = this.blockSize;
  }

  this.buf[this.bufOff++] = input;
  return resultLen;
}

CTS.prototype.processBytes = function(input, inOff, len, out, outOff) {
  if(len < 0) throw new Error("Can't have a negative input length!");
  var blockSize = this.getBlockSize();
  var length = this.getUpdateOutputSize(len);
  
  if(length > 0) {
    if((outOff + length) > out.length) {
      throw new Error("output buffer too short");
    }
  }

  var resultLen = 0;
  var gapLen = this.buf.length - this.bufOff;

  if(len > gapLen) {
    util.copy(this.buf, this.bufOff, input, inOff, gapLen);
    resultLen += this.cipher.processBlock(this.buf, 0, out, outOff);
    util.copy(this.buf, 0, this.buf, blockSize, blockSize);
    this.bufOff = blockSize;

    len -= gapLen;
    inOff += gapLen;

    while(len > blockSize) {
      util.copy(this.buf, this.bufOff, input, inOff, blockSize);
      resultLen += this.cipher.processBlock(this.buf, 0, out, outOff + resultLen);
      util.copy(this.buf, 0, this.buf, blockSize, blockSize);

      len -= blockSize;
      inOff += blockSize;
    }
  }

  util.copy(this.buf, this.bufOff, input, inOff, len);
  this.bufOff += len;
  return resultLen;
}

CTS.prototype.doFinal = function(out, outOff) {
  if(this.bufOff + outOff > out.length) throw new Error("output buffer to small in doFinal");

  var blockSize = this.cipher.getBlockSize();
  var len = this.bufOff - blockSize;
  var block = new Array(blockSize);

  if(this.forEncryption) {
    this.cipher.processBlock(this.buf, 0, block, 0);

    if(this.bufOff < blockSize) throw new Error("need at least one block of input for CTS");

    for(var i = this.bufOff; i != this.buf.length; i++) {
      this.buf[i] = block[i - blockSize];
    }

    for(var i = blockSize; i != this.bufOff; i++) {
      this.buf[i] ^= block[i - blockSize];
    }
    
    if(this.cipher.getAlgorithmName().indexOf("CBC") != -1) {
      var c = this.cipher.getUnderlyingCipher();
      c.processBlock(this.buf, blockSize, out, outOff);
    } else {
      this.cipher.processBlock(this.buf, blockSize, out, outOff);
    }

    util.copy(out, outOff + blockSize, block, 0, len);
  } else {
    var lastBlock = new Array(blockSize);

    if(this.cipher.getAlgorithmName().indexOf("CBC") != -1) {
      var c = this.cipher.getUnderlyingCipher();
      c.processBlock(this.buf, 0, block, 0);
    } else {
      this.cipher.processBlock(this.buf, 0, block, 0);
    }

    for(var i = blockSize; i != this.bufOff; i++) {
      lastBlock[i - blockSize] = (block[i - blockSize] ^ this.buf[i]);
    }

    util.copy(block, 0, this.buf, blockSize, len);
    this.cipher.processBlock(block, 0, out, outOff);
    util.copy(out, outOff + blockSize, lastBlock, 0, len);
  }

  var offset = this.bufOff;
  this.reset();
  return offset;
}

