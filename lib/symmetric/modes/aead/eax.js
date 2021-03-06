var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  SIC = require('symmetric/modes/sic').SIC,
  CBCBlockCipherMac = require('mac/cbcblockciphermac').CBCBlockCipherMac;

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

const nTAG = 0x00;
const hTAG = 0x01;
const cTAG = 0x02;

var EAX = exports.EAX = function(cipher) {
  if(cipher != null) {
    this.blockSize = cipher.getBlockSize();
    this.mac = new CMac(this.cipher);
    
    // this.cipher = cipher;
    // this.blockSize = cipher.getBlockSize();
    // this.macBlock = zeroedData(this.blockSize);
    // if(this.blockSize != 16) throw new Error("cipher required with a block size of 16.");
  }
}

// CCM.prototype.getUnderlyingCipher = function() {
//   return cipher;
// }
// 
// // Initialize object
// //  Two types
// //  Nonce based: init(true, false, key, macSize, nonce, associatedText);
// //  IV based: init(true, true, key, iv);
// CCM.prototype.init = function(forEncryption, withIv) {
//   var args = Array.prototype.slice.call(arguments, 2);
//   
//   // If we are preparing with nonce
//   if(!withIv && args.length == 4) {
//     this.keyParam = args.length ? args.shift() : null; 
//     this.macSize = args.length ? args.shift() / 8 : null; 
//     this.nonce = args.length ? args.shift() : null; 
//     this.associatedText = args.length ? args.shift() : null;     
//   } else if(withIv && args.length == 2){
//     this.keyParam = args.length ? args.shift() : null; 
//     this.macSize = this.macBlock.length / 2; 
//     this.nonce = args.length ? args.shift() : null; 
//     this.associatedText = null;         
//   } else {
//     throw new Error("invalid parameters passed to CCM");
//   }
//   
//   // Set encrypting
//   this.forEncryption = forEncryption;  
//   // Set empty data buffer
//   this.data = [];
// }
// 
// CCM.prototype.getAlgorithmName = function() {
//   return this.cipher.getAlgorithmName() + "/CCM";
// }
// 
// CCM.prototype.getBlockSize = function() {
//   return this.cipher.getBlockSize();
// }
// 
// CCM.prototype.processByte = function(input, out, outOff) {
//   // Add byte to the end of the data buffer
//   this.data[this.data.length] = input;
//   return 0;
// }
// 
// CCM.prototype.processBytes = function(input, inOff, inLen, out, outOff) {
//   inOff = inOff == null ? 0 : inOff;
//   // Write content to data buffer
//   for(var i = inOff; i < (inOff  + inLen); i++) {
//     this.data[this.data.length] = input[i];
//   }
//   
//   return 0;
// }
// 
// CCM.prototype.doFinal = function(output, index) {  
//   index = index == null ? 0 : index;
// 
//   // Encode the data
//   var enc = processPacket(this, this.data, 0, this.data.length);
//   
//   // Copy to output
//   for(var i = 0; i < enc.length; i++) {
//     output[index + i] = enc[i];
//   }
// 
//   // Reset cipher
//   this.reset();
//   // Return length of encoded data
//   return enc.length;
// }
// 
// CCM.prototype.getMac = function() {  
//   // Return the appropriate mac
//   return this.macBlock.slice(0, this.macSize);
// }
// 
// CCM.prototype.getUpdateOutputSize = function(len) {  
//   return 0;
// }
// 
// CCM.prototype.getOutputSize = function(len) {  
//   len = len == null ? 0 : len;
//   
//   if(this.forEncryption) {
//     return this.data.length + len + this.macSize;
//   } else {
//     return this.data.length + len - this.macSize;
//   }
// }
// 
// var processPacket = function(self, input, inOff, inLen) {
//   inOff = inOff == null ? 0 : inOff;
//   if(self.keyParam == null) throw new Error("CCM cipher unitialized.");
//     
//   // CTR Cipher
//   var ctrCipher = new SIC(self.cipher);
//   var iv = [0];
//   var out = null;
//   
//   // Set up first iv byte
//   iv[0] = (((15 - self.nonce.length) - 1) & 0x7);
//   // Copy over nonce to iv
//   iv = iv.concat(self.nonce.slice(0));
//   
//   // Initialize ctr cipher
//   ctrCipher.init(self.forEncryption, iv, self.keyParam);
//     
//   if(self.forEncryption) {
//     var index = inOff;
//     var outOff = 0;
//     // Copy the input to output and add space for the mac
//     var out = input.slice(0).concat(zeroedData(self.macSize));
// 
//     // Calculate mac
//     calculateMac(self, input, inOff, inLen, self.macBlock);
//         
//     // Process block
//     ctrCipher.processBlock(self.macBlock, 0, self.macBlock, 0);
// 
//     // Finish processing blocks
//     while(index < (inLen - self.blockSize)) {
//       ctrCipher.processBlock(input, index, out, outOff);
//       outOff = outOff + self.blockSize;
//       index = index + self.blockSize;
//     }
//     
//     // Copy leftover bytes
//     var block = zeroedData(self.blockSize);
//     for(var i = 0; i < (inLen - index); i++) {
//       block[i] = input[index + i];
//     }
//     
//     // Process last block
//     ctrCipher.processBlock(block, 0, block, 0);
//     
//     // copy last block to index
//     for(var i = 0; i < (inLen - index); i++) {
//       out[index + i] = block[i];
//     }
//     
//     // Append the macblock to the end off the output buffer
//     for(var i = 0; i < self.macSize; i++) {
//       out[inLen + i] = self.macBlock[i];
//     }
//   } else {
//     var index = inOff;
//     var outOff = 0;
//     
//     out = zeroedData(inLen - self.macSize);
//     // Copy from input to macblock
//     util.copy(self.macBlock, 0, input, inOff + inLen - self.macSize, self.macSize);
// 
//     // Decrypt the macblock
//     ctrCipher.processBlock(self.macBlock, 0, self.macBlock, 0);
// 
//     for(var i = self.macSize; i != self.macBlock.length; i++) {
//       self.macBlock[i] = 0;
//     }
//     
//     while(outOff < out.length - self.blockSize) {
//       ctrCipher.processBlock(input, index, out, outOff);
//       outOff = outOff + self.blockSize;
//       index = index + self.blockSize;
//     }
//     
//     var block = zeroedData(self.blockSize);
//     util.copy(block, 0, input, index, out.length - outOff);
//     ctrCipher.processBlock(block, 0, block, 0);
// 
//     util.copy(out, outOff, block, 0, out.length - outOff);
//     var calculatedMacBlock = zeroedData(self.blockSize);
//     calculateMac(self, out, 0, out.length, calculatedMacBlock);
//     
//     if(constantTimeAreEqual(self.macBlock, calculatedMacBlock)) {
//       throw new Error("mac check in CCM failed");
//     }
//   }
//   
//   return out;
// }
// 
// var constantTimeAreEqual = function(a, b) {
//   if(a == null || b == null) {
//     return false;
//   }
// 
//   if(a.length != b.length) {
//     return false;
//   }
// 
//   var nonEqual = 0;
// 
//   for(var i = 0; i != a.length; i++) {
//     nonEqual |= (a[i] ^ b[i]);
//   }
// 
//   return nonEqual == 0;  
// }
// 
// var calculateMac = function(self, data, dataOff, dataLen, macBlock) {
//   var cMac = new CBCBlockCipherMac(self.cipher, self.macSize * 8);
//   cMac.init(self.keyParam);
//   
//   //
//   // build b0
//   //
//   var b0 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//   
//   if(hasAssociatedText(self)) {
//     b0[0] |= 0x40;
//   }
//   
//   b0[0] |= (((cMac.getMacSize() - 2) / 2) & 0x7) << 3;
//   b0[0] |= ((15 - self.nonce.length) - 1) & 0x7;
//   
//   for(var i = 0; i < self.nonce.length; i++) {
//     b0[i + 1] = self.nonce[i];
//   }
// 
//   var q = dataLen;
//   var count = 1;
//   while(q > 0) {
//     b0[b0.length - count] = (q & 0xff);
//     q >>>= 8;
//     count++;    
//   }
// 
//   cMac.update(b0, 0, b0.length);
//   
//   //
//   // process associated text
//   //  
//   if(hasAssociatedText(self)) {
//     var extra = 0;
//     
//     if(self.associatedText.length < ((1 << 16) - (1 << 8))) {
//       cMac.update((self.associatedText.length >> 8));
//       cMac.update(self.associatedText.length);
//       extra = 2;
//     } else {      
//       cMac.update(0xff);
//       cMac.update(0xfe);
//       cMac.update((self.associatedText.length >> 24));
//       cMac.update((self.associatedText.length >> 16));
//       cMac.update((self.associatedText.length >> 8));
//       cMac.update(self.associatedText.length);      
//       extra = 6;      
//     }
//     
//     cMac.update(self.associatedText, 0, self.associatedText.length);
//         
//     extra = (extra + self.associatedText.length) % 16;
//     if(extra != 0) {
//       for(var i = 0; i != 16 - extra; i++) {
//         cMac.update(0x00);
//       }
//     }  
//   }
//   
//   //
//   // add the text
//   //
//   cMac.update(data, dataOff, dataLen);
//   return cMac.doFinal(self.macBlock, 0);
// }
// 
// var hasAssociatedText = function(self) {
//   return self.associatedText != null && self.associatedText.length != 0;
// }
// 
// CCM.prototype.reset = function() {
//   this.cipher.reset();
//   this.data = [];
// }












