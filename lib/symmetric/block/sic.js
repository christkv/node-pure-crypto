var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

var SIC = exports.SIC = function(cipher) {
  if(cipher != null) {    
    this.cipher = cipher;
    this.blockSize = cipher.getBlockSize();
    this.IV = zeroedData(this.blockSize);
    this.counter = zeroedData(this.blockSize);
    this.counterOut = zeroedData(this.blockSize);      
  }
}

SIC.prototype.getUnderlyingCipher = function() {
  return cipher;
}

SIC.prototype.init = function(encrypting, iv) {
  var args = Array.prototype.slice.call(arguments, 1);
  iv = args.length ? args.shift() : null; 
  
  if(iv != null) {
    // Copy iv
    // this.IV = iv.slice(0, this.IV.length);
    for(var i = 0; i < iv.length; i++) {
      this.IV[i] = iv[i];
    }
    // Reset the cipher
    this.reset();    
    // Initialize the cipher with all other parameters
    this.cipher.init.apply(this.cipher, [true].concat(args));
  } else {
    throw new Error("SIC mode requires ParametersWithIV");
  }
}

SIC.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName() + "/SIC";
}

SIC.prototype.getBlockSize = function() {
  return this.cipher.getBlockSize();
}

SIC.prototype.processBlock = function(input, index, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;
  
  // Encrypt the block
  this.cipher.processBlock(this.counter, 0, this.counterOut, 0);

  // debug("------------------------------------------- SIC : 0")
  // debug(util.toHex(this.counter))
  // debug(util.toHex(this.counterOut))
  
  //
  // XOR the counterOut with the plaintext producing the cipher text
  //
  for(var i = 0; i < this.counterOut.length; i++) {
    out[outOff + i] = (this.counterOut[i] ^ input[index + i]);
  }
  
  var carry = 1;
  for(var i = this.counter.length - 1; i >= 0; i--) {
    var x = (this.counter[i] & 0xff) + carry;
    
    if(x > 0xff) {
      carry = 1;
    } else {
      carry = 0;
    }
    
    this.counter[i] = x;
  }
  
  // Return the counter length
  return this.counter.length;
}

SIC.prototype.reset = function() {
  this.counter = this.IV.slice(0, this.counter.length);
  this.cipher.reset();
}