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

var CFBBlockCipherMac = exports.CFBBlockCipherMac = function(cipher, cfbBitSize, macSizeInBits, padding) {
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
  
      this.cipher = new MacCFBBlockCipher(cipher, cfbBitSize);
      this.mac = zeroedArray(cipher.getBlockSize());
      this.buf = zeroedArray(cipher.getBlockSize());  
      this.bufOff = 0;    
    }  
}

CFBBlockCipherMac.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName();
}

CFBBlockCipherMac.prototype.init = function(key, iv) {
  this.reset();
  this.cipher.init(true, key, iv);
}

CFBBlockCipherMac.prototype.getMacSize = function() {
  return this.macSize;
}

CFBBlockCipherMac.prototype.update = function(input, inOff, len) {
  inOff = inOff == null ? 0 : inOff;
  
  if(!Array.isArray(input)) {
    input = [input];    
    len = 1;
  } else {
    len = len == null ? input.length : len;
  }
  
  if(len < 0) throw new Error("Can't have a negative input length!");
  
  var blockSize = this.cipher.getBlockSize();
  var resultLen = 0;
  var gapLen = blockSize - this.bufOff;

  if (len > gapLen) {
    util.copy(this.buf, this.bufOff, input, inOff, gapLen);
    resultLen += this.cipher.processBlock(this.buf, 0, this.mac, 0);
    
    this.bufOff = 0;
    len -= gapLen;
    inOff += gapLen;

    while (len > blockSize) {
      resultLen += this.cipher.processBlock(input, inOff, this.mac, 0);

      len -= blockSize;
      inOff += blockSize;
    }
  }

  util.copy(this.buf, this.bufOff, input, inOff, len);
  this.bufOff += len;  
}

CFBBlockCipherMac.prototype.doFinal = function(out, outOff) {
  var blockSize = this.cipher.getBlockSize();

  //
  // pad with zeroes
  //
  if (this.padding == null) {
    while(this.bufOff < blockSize) {
      this.buf[this.bufOff] = 0;
      this.bufOff++;
    }
  } else {
    this.padding.addPadding(this.buf, this.bufOff);
  }

  this.cipher.processBlock(this.buf, 0, this.mac, 0);
  this.cipher.getMacBlock(this.mac);
  util.copy(out, outOff, this.mac, 0, this.macSize);

  this.reset();
  return this.macSize;
}

CFBBlockCipherMac.prototype.reset = function() {
  /*
   * clean the buffer.
   */
  for(var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }

  this.bufOff = 0;

  /*
   * reset the underlying cipher.
   */
  this.cipher.reset();  
}

var MacCFBBlockCipher = function(cipher, bitBlockSize) {
  this.cipher = cipher;
  this.blockSize = bitBlockSize / 8;
  this.IV = zeroedArray(cipher.getBlockSize());
  this.cfbV = zeroedArray(cipher.getBlockSize());
  this.cfbOutV = zeroedArray(cipher.getBlockSize());  
}

MacCFBBlockCipher.prototype.init = function(forEncryption, key, iv) {
  if(iv != null) {
    if(iv.length < this.IV.length) {
      util.copy(this.IV, (this.IV.length - iv.length), iv, 0, iv.length);
    } else {
      util.copy(this.IV, 0, iv, 0, this.IV.length);
    }    

    this.reset();  
    this.cipher.init(true, key);
  } else {
    this.reset();  
    this.cipher.init(true, key);
  }
}

MacCFBBlockCipher.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName() + "/CFB" + (this.blockSize * 8);
}

MacCFBBlockCipher.prototype.getBlockSize = function() {
  return this.blockSize;
}

MacCFBBlockCipher.prototype.processBlock = function(input, inOff, out, outOff) {
  if ((inOff + this.blockSize) > input.length) {
    throw new Error("input buffer too short");
  }

  if ((outOff + this.blockSize) > out.length) {
    throw new Error("output buffer too short");
  }

  this.cipher.processBlock(this.cfbV, 0, this.cfbOutV, 0);

  //
  // XOR the cfbV with the plaintext producing the cipher text
  //
  for (var i = 0; i < this.blockSize; i++) {
    out[outOff + i] = (this.cfbOutV[i] ^ input[inOff + i]);
  }

  //
  // change over the input block.
  //
  util.copy(this.cfbV, 0, this.cfbV, this.blockSize, this.cfbV.length - this.blockSize)
  util.copy(this.cfbV, this.cfbV.length - this.blockSize, out, outOff, this.blockSize);
  return this.blockSize;
} 

MacCFBBlockCipher.prototype.reset = function() {
  this.cfbV = this.IV.slice(0);
  this.cipher.reset();
}

MacCFBBlockCipher.prototype.getMacBlock = function(mac) {
  return this.cipher.processBlock(this.cfbV, 0, mac, 0);
}