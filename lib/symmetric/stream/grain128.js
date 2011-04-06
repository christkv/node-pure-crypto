var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

const STATE_SIZE = 4;

var Grain128 = exports.Grain128 = function(key, iv) {  
  if(iv == null || iv.length != 12) throw "Grain v1 requires exactly 12 bytes of IV";
  if(key == null) throw "Grain v1 Init parameters must include a key";
  // 
  // Initialize variables
  this.workingIV = iv.slice(0);
  this.workingKey = key.slice(0);
  this.lfsr = new Array(STATE_SIZE);
  this.nfsr = new Array(STATE_SIZE);
  this.out = new Array(4);
  this.output = 0;
  this.index = 4;
  
  // Setkey
  this.workingIV[12] = 0xFF;
  this.workingIV[13] = 0xFF;
  this.workingIV[14] = 0xFF;
  this.workingIV[15] = 0xFF;
  
  /**
   * Load NFSR and LFSR
   */
  var j = 0;
  for (var i = 0; i < this.nfsr.length; i++) {
    this.nfsr[i] = ((this.workingKey[j + 3]) << 24) | ((this.workingKey[j + 2]) << 16)
        & 0x00FF0000 | ((this.workingKey[j + 1]) << 8) & 0x0000FF00
        | ((this.workingKey[j]) & 0x000000FF);

    this.lfsr[i] = ((this.workingIV[j + 3]) << 24) | ((this.workingIV[j + 2]) << 16)
        & 0x00FF0000 | ((this.workingIV[j + 1]) << 8) & 0x0000FF00
        | ((this.workingIV[j]) & 0x000000FF);
    j += 4;
  }
  
  // Init grain
  for(var i = 0; i < 8; i++) {
    this.output = this.getOutput();
    this.nfsr = shift(this.nfsr, this.getOutputNFSR() ^ this.lfsr[0] ^ this.output);
    this.lfsr = shift(this.lfsr, this.getOutputLFSR() ^ this.output);
  }  
  
  // debug("================================================== nfsr")
  // for(var i = 0; i < this.nfsr.length; i++) {
  //   debug("nfsr[" + i + "] = " + this.nfsr[i].toString(16));
  // }

  // debug("================================================== lfsr")
  // for(var i = 0; i < this.lfsr.length; i++) {
  //   debug("lfsr[" + i + "] = " + this.lfsr[i].toString(16));
  // }

  // debug("================================================== workingKey")
  // for(var i = 0; i < this.workingKey.length; i++) {
  //   debug("workingKey[" + i + "] = " + this.workingKey[i].toString(16));
  // }

  // debug("================================================== workingIV")
  // for(var i = 0; i < this.workingIV.length; i++) {
  //   debug("workingIV[" + i + "] = " + this.workingIV[i].toString(16));
  // }
  
}

// Get output from non-linear function g(x).
Grain128.prototype.getOutputNFSR = function() {
  var b0 = this.nfsr[0];
  var b3 = this.nfsr[0] >>> 3 | this.nfsr[1] << 29;
  var b11 = this.nfsr[0] >>> 11 | this.nfsr[1] << 21;
  var b13 = this.nfsr[0] >>> 13 | this.nfsr[1] << 19;
  var b17 = this.nfsr[0] >>> 17 | this.nfsr[1] << 15;
  var b18 = this.nfsr[0] >>> 18 | this.nfsr[1] << 14;
  var b26 = this.nfsr[0] >>> 26 | this.nfsr[1] << 6;
  var b27 = this.nfsr[0] >>> 27 | this.nfsr[1] << 5;
  var b40 = this.nfsr[1] >>> 8 | this.nfsr[2] << 24;
  var b48 = this.nfsr[1] >>> 16 | this.nfsr[2] << 16;
  var b56 = this.nfsr[1] >>> 24 | this.nfsr[2] << 8;
  var b59 = this.nfsr[1] >>> 27 | this.nfsr[2] << 5;
  var b61 = this.nfsr[1] >>> 29 | this.nfsr[2] << 3;
  var b65 = this.nfsr[2] >>> 1 | this.nfsr[3] << 31;
  var b67 = this.nfsr[2] >>> 3 | this.nfsr[3] << 29;
  var b68 = this.nfsr[2] >>> 4 | this.nfsr[3] << 28;
  var b84 = this.nfsr[2] >>> 20 | this.nfsr[3] << 12;
  var b91 = this.nfsr[2] >>> 27 | this.nfsr[3] << 5;
  var b96 = this.nfsr[3];

  return b0 ^ b26 ^ b56 ^ b91 ^ b96 ^ b3 & b67 ^ b11 & b13 ^ b17 & b18
      ^ b27 & b59 ^ b40 & b48 ^ b61 & b65 ^ b68 & b84;
}

// Get output from linear function f(x).
Grain128.prototype.getOutputLFSR = function() {
  var s0 = this.lfsr[0];
  var s7 = this.lfsr[0] >>> 7 | this.lfsr[1] << 25;
  var s38 = this.lfsr[1] >>> 6 | this.lfsr[2] << 26;
  var s70 = this.lfsr[2] >>> 6 | this.lfsr[3] << 26;
  var s81 = this.lfsr[2] >>> 17 | this.lfsr[3] << 15;
  var s96 = this.lfsr[3];
  return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
}

// Get output from output function h(x).
Grain128.prototype.getOutput = function() {
  var b2 = this.nfsr[0] >>> 2 | this.nfsr[1] << 30;
  var b12 = this.nfsr[0] >>> 12 | this.nfsr[1] << 20;
  var b15 = this.nfsr[0] >>> 15 | this.nfsr[1] << 17;
  var b36 = this.nfsr[1] >>> 4 | this.nfsr[2] << 28;
  var b45 = this.nfsr[1] >>> 13 | this.nfsr[2] << 19;
  var b64 = this.nfsr[2];
  var b73 = this.nfsr[2] >>> 9 | this.nfsr[3] << 23;
  var b89 = this.nfsr[2] >>> 25 | this.nfsr[3] << 7;
  var b95 = this.nfsr[2] >>> 31 | this.nfsr[3] << 1;
  var s8 = this.lfsr[0] >>> 8 | this.lfsr[1] << 24;
  var s13 = this.lfsr[0] >>> 13 | this.lfsr[1] << 19;
  var s20 = this.lfsr[0] >>> 20 | this.lfsr[1] << 12;
  var s42 = this.lfsr[1] >>> 10 | this.lfsr[2] << 22;
  var s60 = this.lfsr[1] >>> 28 | this.lfsr[2] << 4;
  var s79 = this.lfsr[2] >>> 15 | this.lfsr[3] << 17;
  var s93 = this.lfsr[2] >>> 29 | this.lfsr[3] << 3;
  var s95 = this.lfsr[2] >>> 31 | this.lfsr[3] << 1;

  return b12 & s8 ^ s13 & s20 ^ b95 & s42 ^ s60 & s79 ^ b12 & b95 & s95 ^ s93
      ^ b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89;
}

// Shift array 16 bits and add val to index.length - 1.
var shift = function(array, val) {
  array[0] = array[1];
  array[1] = array[2];
  array[2] = array[3];
  array[3] = val;
  return array;
}

Grain128.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src);
}

Grain128.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Grain128.prototype.finalEncrypt = function() {
  return "";  
}

Grain128.prototype.encryptStream = function(src) {
  var self = this;
  
  for(var i = 0; i < src.length; i++) {
    src[i] = src[i] ^ this.getKeyStream();
  }
  
  // Return encrypted buffer
  return src;
}

Grain128.prototype.getKeyStream = function() {
  if(this.index > 3) {
    this.oneRound();
    this.index = 0;
  }
  return this.out[this.index++];
}

Grain128.prototype.oneRound = function() {
  this.output = this.getOutput();
  // Map the output
  this.out[3] = (this.output >> 24) & 0xff;
  this.out[2] = (this.output >> 16) & 0xff;
  this.out[1] = (this.output >> 8) & 0xff;
	this.out[0] = this.output & 0xff;
  // Update state tables
  this.nfsr = shift(this.nfsr, this.getOutputNFSR() ^ this.lfsr[0]);
  this.lfsr = shift(this.lfsr, this.getOutputLFSR());  
}

Grain128.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src);
}

Grain128.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Grain128.prototype.finalDecrypt = function() {
  return "";  
}
