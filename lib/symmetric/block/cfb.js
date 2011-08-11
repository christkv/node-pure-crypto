var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

var CFB = exports.CFB = function(cipher, bitBlockSize) {
  if(cipher != null) {
    this.cipher = cipher;
    this.blockSize = bitBlockSize == null ? this.cipher.getBlockSize() * 8 : bitBlockSize;
    this.blockSize = this.blockSize / 8;
    this.IV = zeroedData(this.cipher.getBlockSize());
    this.cfbV = zeroedData(this.cipher.getBlockSize());
    this.cfbOutV = zeroedData(this.cipher.getBlockSize());
  }
}

CFB.prototype.init = function(encrypting, withIv, iv) {
  var args = Array.prototype.slice.call(arguments, 2);
  // Set encrypting
  this.encrypting = encrypting; 
     
  // If we are preparing with nonce
  if(withIv && args.length == 2) {
    if(iv.length != this.blockSize) throw new Error("initialisation vector must be the same length as block size");
    // Get iv
    var iv = args.length ? args.shift() : null;
    
    // If we are missing iv size prepend 0's
    if(iv.length < this.IV.length) {
      for(var i = 0; i < this.IV.length - iv.length; i++) {
        this.IV[i] = 0;
      }
    } else {
      this.IV = iv.slice(0);
    }
    this.reset();
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [true].concat(args));
  } else {
    this.reset();
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [true].concat(args));
  }
}

CFB.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName() + "/CFB" + (this.blockSize * 8);
}

CFB.prototype.getBlockSize = function() {
  return this.blockSize;
}

CFB.prototype.processBlock = function(input, index, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;
  return this.encrypting ? encryptBlock(this, input, index, out, outOff) : decryptBlock(this, input, index, out, outOff)
}

var encryptBlock = function(self, input, inOff, out, outOff) {
  if((inOff + self.blockSize) > input.length) throw new Error("input buffer too short");
  if((outOff + self.blockSize) > out.length) throw new Error("output buffer too short");    
  self.cipher.processBlock(self.cfbV, 0, self.cfbOutV, 0);
  
  // XOR the cfbV with the plaintext producing the ciphertext
  for(var i = 0; i < self.blockSize; i++) {
    out[outOff + i] = self.cfbOutV[i] ^ input[inOff + i];
  }

  // change over the input block.
  util.copy(self.cfbV, 0, self.cfbV, self.blockSize, self.cfbV.length - self.blockSize);
  util.copy(self.cfbV, self.cfbV.length - self.blockSize, out, outOff, self.blockSize);
  return self.blockSize;  
}

var decryptBlock = function(self, input, inOff, out, outOff) {
  if((inOff + self.blockSize) > input.length) throw new Error("input buffer too short");
  if((outOff + self.blockSize) > out.length) throw new Error("output buffer too short");
  self.cipher.processBlock(self.cfbV, 0, self.cfbOutV, 0);
  
  // change over the input block.
  util.copy(self.cfbV, 0, self.cfbV, self.blockSize, self.cfbV - self.blockSize);
  util.copy(self.cfbV, self.cfbV.length - self.blockSize, input, inOff, self.blockSize);
  
  // XOR the cfbV with the ciphertext producing the plaintext
  for(var i = 0; i < self.blockSize; i++) {
    out[outOff + i] = self.cfbOutV[i] ^ input[inOff + i];
  }  
  return self.blockSize;
}

CFB.prototype.reset = function() {
  this.cfbV = this.IV.slice(0);
  this.cipher.reset();
}

