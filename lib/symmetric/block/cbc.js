var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

var CBC = exports.CBC = function(cipher) {
  if(cipher != null) {
    this.cipher = cipher;
    this.blockSize = cipher.getBlockSize();

    this.IV = zeroedData(this.blockSize);
    this.cbcV = zeroedData(this.blockSize);
    this.cbcNextV = zeroedData(this.blockSize);    
  }
}

CBC.prototype.getUnderlyingCipher = function() {
  return cipher;
}

CBC.prototype.init = function(encrypting, withIv, iv) {
  var args = Array.prototype.slice.call(arguments, 2);
  // Set encrypting
  this.encrypting = encrypting;  
  // If we are preparing with nonce
  if(withIv && args.length == 2) {
    if(iv.length != this.blockSize) throw new Error("initialisation vector must be the same length as block size");
    // Get iv
    var iv = args.length ? args.shift() : null;
    this.IV = iv.slice(0);    
    this.reset();
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [encrypting].concat(args));    
  } else {
    this.reset();
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [encrypting].concat(args));    
  }
}

CBC.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName() + "/CBC";
}

CBC.prototype.getBlockSize = function() {
  return this.cipher.getBlockSize();
}

CBC.prototype.processBlock = function(input, index, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;
  return this.encrypting ? encryptBlock(this, input, index, out, outOff) : decryptBlock(this, input, index, out, outOff)
}

var encryptBlock = function(self, input, index, out, outOff) {
  if((index + self.blockSize) > input.length) throw new Error("input buffer too short");
  // Xor against iv stream
  for(var i = 0; i < self.blockSize; i++) {
    self.cbcV[i] = self.cbcV[i] ^ input[index + i];
  }
  
  // Encrypt the content
  var length = self.cipher.processBlock(self.cbcV, 0, out, outOff)  
  
  // Copy content over existing location
  util.copy(self.cbcV, 0, out, outOff, self.cbcV.length);
  return length;  
}

var decryptBlock = function(self, input, index, out, outOff) {
  if((index + self.blockSize) > input.length) throw new Error("input buffer too short");

  // Get block for decryption
  self.cbcNextV = input.slice(index, index + self.blockSize);
  // Decrypt the content
  var length = self.cipher.processBlock(input, index, out, outOff);

  // Remove the cbc stream  
  for(var i = 0; i < self.blockSize; i++) {
    out[outOff + i] = out[outOff + i] ^ self.cbcV[i];
  }
  
  // Swap the buffer into the next position
  var tmp = self.cbcV;
  self.cbcV = self.cbcNextV;
  self.cbcNextV = tmp;
  return length;
}

CBC.prototype.reset = function() {
  this.cbcV = this.IV.slice(0);
  this.cbcNextV = zeroedData(this.blockSize);
  this.cipher.reset();
}