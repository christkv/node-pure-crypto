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

    this.IV = new zeroedData(this.blockSize);
    this.cbcV = new zeroedData(this.blockSize);
    this.cbcNextV = new zeroedData(this.blockSize);    
  }
}

CBC.prototype.getUnderlyingCipher = function() {
  return cipher;
}

CBC.prototype.init = function(encrypting, iv) {
  var args = Array.prototype.slice.call(arguments, 1);
  iv = args.length ? args.shift() : null; 
  // Set encrypting
  this.encrypting = encrypting;
  
  if(iv != null) {
    if(iv.length != this.blockSize) throw new Error("initialisation vector must be the same length as block size");
    // Copy iv
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

CBC.prototype.processBlock = function(input, index) {
  index = index == null ? 0 : index;
  return this.encrypting ? encryptBlock(this, input, index) : decryptBlock(this, input, index)
}

var encryptBlock = function(self, input, index) {
  if((index + self.blockSize) > input.length) throw new Error("input buffer too short");

  // Xor against iv stream
  for(var i = 0; i < self.blockSize; i++) {
    self.cbcV[i] = self.cbcV[i] ^ input[index + i];
  }
  
  // Encrypt the content
  var length = self.cipher.processBlock(self.cbcV, 0)
  // Copy content over existing location
  for(var i = 0; i < self.blockSize; i++) {
    input[index + i] = self.cbcV[i];
  }
  
  // Encrypt content
  return length;  
}

var decryptBlock = function(self, input, index) {
  if((index + self.blockSize) > input.length) throw new Error("input buffer too short");

  // Get block for decryption
  self.cbcNextV = input.slice(index, index + self.blockSize);
  // Decrypt the content
  var length = self.cipher.processBlock(input, index);

  // Remove the cbc stream  
  for(var i = 0; i < self.blockSize; i++) {
    input[index + i] = input[index + i] ^ self.cbcV[i];
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