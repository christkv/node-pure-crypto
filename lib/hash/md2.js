var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 16;
const BYTE_LENGTH = 16;

var MD2 = exports.MD2 = function() {
  // Call base class constructor
  BaseDigest.call(this);
  // Setup MD2
  this.X = new Array(48);
  this.M = new Array(16);
  this.C = new Array(16);
  this.xOff = 0;
  this.mOff = 0;
  this.COff = 0;  
  // Reset state
  this.reset();
}

inherits(MD2, BaseDigest);

MD2.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

MD2.prototype.getAlgorithmName = function() {
  return "MD2";
}

MD2.prototype.processBlock = function() {
  var self = this;
}

var update = function(self, byte) {
  self.M[self.mOff++] = byte;

  if (self.mOff == 16) {
    processCheckSum(self, self.M);
    processBlock(self, self.M);
    self.mOff = 0;
  }
}

MD2.prototype.update = function(src) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var len = src.length;
  var inOff = 0;
  
  //
  // fill the current word
  //
  while ((this.mOff != 0) && (len > 0)) {
      update(this, src[inOff]);
      inOff++;
      len--;
  }

  //
  // process whole words.
  //
  while (len > 16) {
    this.M = src.slice(inOff, inOff + 16);
    processCheckSum(this, this.M);
    processBlock(this, this.M);
    len -= 16;
    inOff += 16;
  }

  //
  // load in the remainder.
  //
  while (len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }  
}

var processCheckSum = function(self, m) {
  var L = self.C[15];
  for (var i = 0; i < 16; i++) {
    self.C[i] ^= S[(m[i] ^ L) & 0xff];
    L = self.C[i];
  }
}

var processBlock = function(self, m) {
  for (var i = 0; i < 16; i++) {
    self.X[i+16] = m[i];
    self.X[i+32] = (m[i] ^ self.X[i]);
  }
  // encrypt block
  var t = 0;

  for (var j = 0; j < 18; j++) {
    for (var k = 0; k < 48; k++) {
      t = self.X[k] ^= S[t];
      t = t & 0xff;
    }
    t = (t + j)%256;
  }
}

//
// Common to all digests
MD2.prototype.reset = function() {
  this.xOff = 0;
  for(var i = 0; i < this.X.length; i++) this.X[i] = 0;
  this.mOff = 0;
  for(var i = 0; i < this.M.length; i++) this.M[i] = 0;
  this.COff = 0;
  for(var i = 0; i < this.C.length; i++) this.C[i] = 0;
}

//
// Common to all digests
MD2.prototype.doFinal = function(output, index) {
  // add padding
  var paddingByte = this.M.length - this.mOff;
  for (var i = this.mOff; i < this.M.length; i++) {
    this.M[i] = paddingByte;
  }
  
  index = index == null ? 0 : index;
  //do final check sum
  processCheckSum(this, this.M);
  // do final block process
  processBlock(this, this.M);
  processBlock(this, this.C);

  // output of digest
  // var output = this.X.slice(this.xOff, 16);
  for(var i = 0; i < BYTE_LENGTH; i++) {
    output[index + i] = this.X[this.xOff + i];
  }
  
  // reset digest
  this.reset();

  // Return based on encoding
  return BYTE_LENGTH;    
}

 // 256-byte random permutation constructed from the digits of PI
const S = [41,46,67,201,162,216,124,1,61,54,84,161,236,240,6,19,98,167,5,243,192,199,
  115,140,152,147,43,217,188,76,130,202,30,155,87,60,253,212,224,22,103,66,111,24,138,
  23,229,18,190,78,196,214,218,158,222,73,160,251,245,142,187,47,238,122,169,104,121,
  145,21,178,7,63,148,194,16,137,11,34,95,33,128,127,93,154,90,144,50,39,53,62,204,
  231,191,247,151,3,255,25,48,179,72,165,181,209,215,94,146,42,172,86,170,198,79,184,
  56,210,150,164,125,182,118,252,107,226,156,116,4,241,69,157,112,89,100,113,135,32,
  134,91,207,101,230,45,168,2,27,96,37,173,174,176,185,246,28,70,97,105,52,64,126,15,
  85,71,163,35,221,81,175,58,195,92,249,206,186,197,234,38,44,83,13,110,133,40,132, 
  9,211,223,205,244,65,129,77,82,106,220,55,200,108,193,171,250,36,225,123,8,12,189,
  177,74,120,136,149,139,227,99,232,109,233,203,213,254,59,0,29,57,242,239,183,14,102,
  88,208,228,166,119,114,248,235,117,75,10,49,68,80,180,143,237,31,26,219,153,141,51,
  159,17,131,20];
