var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

const STATE_SIZE = 5;

var GrainV1 = exports.GrainV1 = function() {  
}

GrainV1.prototype.init = function(forEncryption, key, iv) {
  if(iv == null || iv.length != 8) throw "Grain v1 requires exactly 8 bytes of IV";
  if(key == null) throw "Grain v1 Init parameters must include a key";

  // Initialize variables
  this.workingIV = iv.slice(0);
  this.workingKey = key.slice(0);
  this.lfsr = new Array(STATE_SIZE);
  this.nfsr = new Array(STATE_SIZE);
  this.out = new Array(2);
  this.output = 0;
  this.index = 2;
  
  // Setkey
  this.workingIV[8] = 0xFF;
  this.workingIV[9] = 0xFF;
  
  /**
   * Load NFSR and LFSR
   */
  var j = 0;
  for (var i = 0; i < this.nfsr.length; i++) {
    this.nfsr[i] = (this.workingKey[j + 1] << 8 | this.workingKey[j] & 0xFF) & 0x0000FFFF;
    this.lfsr[i] = (this.workingIV[j + 1] << 8 | this.workingIV[j] & 0xFF) & 0x0000FFFF;
    j += 2;
  }
  
  // Init grain
  for(var i = 0; i < 10; i++) {
    this.output = this.getOutput();
    this.nfsr = shift(this.nfsr, this.getOutputNFSR() ^ this.lfsr[0] ^ this.output);
    this.lfsr = shift(this.lfsr, this.getOutputLFSR() ^ this.output);
  }    
}

// Get output from non-linear function g(x).
GrainV1.prototype.getOutputNFSR = function() {
  var b0 = this.nfsr[0];
  var b9 = this.nfsr[0] >>> 9 | this.nfsr[1] << 7;
  var b14 = this.nfsr[0] >>> 14 | this.nfsr[1] << 2;
  var b15 = this.nfsr[0] >>> 15 | this.nfsr[1] << 1;
  var b21 = this.nfsr[1] >>> 5 | this.nfsr[2] << 11;
  var b28 = this.nfsr[1] >>> 12 | this.nfsr[2] << 4;
  var b33 = this.nfsr[2] >>> 1 | this.nfsr[3] << 15;
  var b37 = this.nfsr[2] >>> 5 | this.nfsr[3] << 11;
  var b45 = this.nfsr[2] >>> 13 | this.nfsr[3] << 3;
  var b52 = this.nfsr[3] >>> 4 | this.nfsr[4] << 12;
  var b60 = this.nfsr[3] >>> 12 | this.nfsr[4] << 4;
  var b62 = this.nfsr[3] >>> 14 | this.nfsr[4] << 2;
  var b63 = this.nfsr[3] >>> 15 | this.nfsr[4] << 1;

  return (b62 ^ b60 ^ b52 ^ b45 ^ b37 ^ b33 ^ b28 ^ b21 ^ b14
      ^ b9 ^ b0 ^ b63 & b60 ^ b37 & b33 ^ b15 & b9 ^ b60 & b52 & b45
      ^ b33 & b28 & b21 ^ b63 & b45 & b28 & b9 ^ b60 & b52 & b37
      & b33 ^ b63 & b60 & b21 & b15 ^ b63 & b60 & b52 & b45 & b37
      ^ b33 & b28 & b21 & b15 & b9 ^ b52 & b45 & b37 & b33 & b28
      & b21) & 0x0000FFFF;
}

// Get output from linear function f(x).
GrainV1.prototype.getOutputLFSR = function() {
  var s0 = this.lfsr[0];
  var s13 = this.lfsr[0] >>> 13 | this.lfsr[1] << 3;
  var s23 = this.lfsr[1] >>> 7 | this.lfsr[2] << 9;
  var s38 = this.lfsr[2] >>> 6 | this.lfsr[3] << 10;
  var s51 = this.lfsr[3] >>> 3 | this.lfsr[4] << 13;
  var s62 = this.lfsr[3] >>> 14 | this.lfsr[4] << 2;
  return (s0 ^ s13 ^ s23 ^ s38 ^ s51 ^ s62) & 0x0000FFFF;
}

// Get output from output function h(x).
GrainV1.prototype.getOutput = function() {
  var b1 = this.nfsr[0] >>> 1 | this.nfsr[1] << 15;
  var b2 = this.nfsr[0] >>> 2 | this.nfsr[1] << 14;
  var b4 = this.nfsr[0] >>> 4 | this.nfsr[1] << 12;
  var b10 = this.nfsr[0] >>> 10 | this.nfsr[1] << 6;
  var b31 = this.nfsr[1] >>> 15 | this.nfsr[2] << 1;
  var b43 = this.nfsr[2] >>> 11 | this.nfsr[3] << 5;
  var b56 = this.nfsr[3] >>> 8 | this.nfsr[4] << 8;
  var b63 = this.nfsr[3] >>> 15 | this.nfsr[4] << 1;
  var s3 = this.lfsr[0] >>> 3 | this.lfsr[1] << 13;
  var s25 = this.lfsr[1] >>> 9 | this.lfsr[2] << 7;
  var s46 = this.lfsr[2] >>> 14 | this.lfsr[3] << 2;
  var s64 = this.lfsr[4];

  return (s25 ^ b63 ^ s3 & s64 ^ s46 & s64 ^ s64 & b63 ^ s3
      & s25 & s46 ^ s3 & s46 & s64 ^ s3 & s46 & b63 ^ s25 & s46 & b63 ^ s46
      & s64 & b63 ^ b1 ^ b2 ^ b4 ^ b10 ^ b31 ^ b43 ^ b56) & 0x0000FFFF;
}

// Shift array 16 bits and add val to index.length - 1.
var shift = function(array, val) {
    array[0] = array[1];
    array[1] = array[2];
    array[2] = array[3];
    array[3] = array[4];
    array[4] = val;
    return array;
}

GrainV1.prototype.getAlgorithmName = function() {
  return "GRAINV1";
}

GrainV1.prototype.reset = function() {  
}

GrainV1.prototype.returnByte = function(input) {
  return input ^ this.getKeyStream();
}

GrainV1.prototype.processBytes = function(src, index, len, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;
  var self = this;
  
  for(var i = 0; i < len; i++) {
    out[outOff + i] = src[index + i] ^ this.getKeyStream();
  }
}

GrainV1.prototype.getKeyStream = function() {
  if(this.index > 1) {
    this.oneRound();
    this.index = 0;
  }
  return this.out[this.index++];
}

GrainV1.prototype.oneRound = function() {
  this.output = this.getOutput();
  // Map the output
  this.out[1] = (this.output >> 8) & 0xff;
	this.out[0] = this.output & 0xff;
  // Update state tables
  this.nfsr = shift(this.nfsr, this.getOutputNFSR() ^ this.lfsr[0]);
  this.lfsr = shift(this.lfsr, this.getOutputLFSR());  
}