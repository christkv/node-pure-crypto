var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  SIC = require('symmetric/block/sic').SIC;

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

var CCM = exports.CCM = function(cipher) {
  if(cipher != null) {
    this.cipher = cipher;
    this.blockSize = cipher.getBlockSize();
    this.macBlock = zeroedData(this.blockSize);
    if(this.blockSize != 16) throw new Error("cipher required with a block size of 16.");
  }
}

CCM.prototype.getUnderlyingCipher = function() {
  return cipher;
}

// Initialize object
//  Two types
//  Nonce based: init(true, false, key, macSize, nonce, associatedText);
//  IV based: init(true, true, key, iv);
CCM.prototype.init = function(forEncryption, withIv) {
  var args = Array.prototype.slice.call(arguments, 2);
  
  // If we are preparing with nonce
  if(!withIv && args.length == 4) {
    this.keyParam = args.length ? args.shift() : null; 
    this.macSize = args.length ? args.shift() : null; 
    this.nonce = args.length ? args.shift() : null; 
    this.associatedText = args.length ? args.shift() : null;     
  } else if(withIv && args.length == 2){
    this.keyParam = args.length ? args.shift() : null; 
    this.macSize = this.macBlock.length / 2; 
    this.nonce = args.length ? args.shift() : null; 
    this.associatedText = null;         
  } else {
    throw new Error("invalid parameters passed to CCM");
  }
  
  // Set encrypting
  this.forEncryption = forEncryption;  
  // Set empty data buffer
  this.data = [];
}

CCM.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName() + "/CCM";
}

CCM.prototype.getBlockSize = function() {
  return this.cipher.getBlockSize();
}

CCM.prototype.processByte = function(input, index) {
  // Add byte to the end of the data buffer
  this.data[this.data.length] = input;
  return 0;
}

CCM.prototype.processBytes = function(input, index) {
  index = index == null ? 0 : index;
  // Write content to data buffer
  for(var i = index; i < input.length; i++) {
    this.data[this.data.length] = input[i];
  }
  
  return 0;
}

CCM.prototype.doFinal = function(output, index) {  
  index = index == null ? 0 : index;
  // Encode the data
  var enc = processPacket(this, this.data, 0, this.data.length);
  // Copy to output
  for(var i = 0; i < enc.length; i++) {
    output[index + i] = enc[i];
  }
  
  // Reset cipher
  this.reset();
  // Return length of encoded data
  return enc.length;
}

CCM.prototype.getMac = function() {  
  // Return the appropriate mac
  return this.macBlock.slice(0, this.macSize);
}

CCM.prototype.getUpdateOutputSize = function(len) {  
  return 0;
}

CCM.prototype.getOutputSize = function(len) {  
  len = len == null ? 0 : len;
  
  if(this.forEncryption) {
    return this.data.length + len + this.macSize;
  } else {
    return this.data.length + len - this.macSize;
  }
}

var processPacket = function(self, input, inOff, inLen) {
  inOff = inOff == null ? 0 : inOff;
  if(self.keyParam == null) throw new Error("CCM cipher unitialized.");
  
  // CTR Cipher
  var ctrCipher = new SIC(self.cipher);
  var iv = [0];
  var out = null;
  
  // Set up first iv byte
  iv[0] = (((15 - self.nonce.length) - 1) & 0x7);
  // Copy over nonce to iv
  iv = iv.concat(self.nonce.slice(0));
  
  // Initialize ctr cipher
  ctrCipher.init(self.forEncryption, iv, self.keyParam);
  
  if(self.forEncryption) {
    var index = inOff;
    // Copy the input to output and add space for the mac
    var out = input.slice(0).concat(zeroedData(self.macSize));
    // Calculate mac
    calculateMac(self, input, inOff, inLen, self.macBlock);
    // Process block
    ctrCipher.processBlock(self.macBlock, 0);
    
    // Finish processing blocks
    while(index < (inLen - self.blockSize)) {            
      ctrCipher.processBlock(out, index);
      index = index + self.blockSize;
    }
    
    // Copy leftover bytes
    var block = new Array(self.blockSize);
    for(var i = 0; i < (inLen - index); i++) {
      block[i] = input[index + i];
    }
    
    // Process last block
    ctrCipher.processBlock(block, 0);
    
    // copy last block to index
    for(var i = 0; i < (inLen - index); i++) {
      out[index + i] = block[i];
    }
    
    // Append the macblock to the end off the output buffer
    for(var i = 0; i < self.macSize; i++) {
      out[inLen + i] = self.macBlock[i];
    }
  } else {
    
  }
}

var calculateMac = function(self, data, dataOff, dataLen, macBlock) {
  var cMac = new CBCBlockCipherMac(self.cipher, self.macSize * 8);
  cMac.init(self.keyParam);
  
  //
  // build b0
  //
  var b0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  
  if(hasAssociatedText(this)) {
    var extra = 0;
    
    if(this.associatedText.length < ((1 << 16) - (1 << 8))) {
      cMac.update((this.associatedText.length >> 8));
      cMac.update(this.associatedText.length);
      extra = 2;
    } else {
      cMac.update(0xff);
      cMac.update(0xfe);
      cMac.update((this.associatedText.length >> 24));
      cMac.update((this.associatedText.length >> 16));
      cMac.update((this.associatedText.length >> 8));
      cMac.update(this.associatedText.length);      
      extra = 6;      
    }
    
    cMac.update(this.associatedText, 0, associatedText.length);
    
    extra = (extra + this.associatedText.length) % 16;
    if (extra != 0) {
      for(var i = 0; i != 16 - extra; i++) {
        cMac.update(0x00);
      }
    }  
  }
  
  //
  // add the text
  //
  cMac.update(data, dataOff, dataLen);
  return cMac.doFinal(macBlock, 0);  
}

var hasAssociatedText = function(self) {
  return self.associatedText != null && self.associatedText.length != 0;
}

CCM.prototype.reset = function() {
  this.cipher.reset();
  this.data = [];
}












