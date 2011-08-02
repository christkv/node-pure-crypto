var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

var ISAAC = exports.ISAAC = function() {
}

ISAAC.prototype.init = function(forEncryption, key, iv) {
  this.sizeL = 8;
  this.stateArraySize = this.sizeL << 5; // 256  
  this.engineState = [this.stateArraySize]; // mm
  this.results = [this.stateArraySize]; // randrsl
  this.a = 0;
  this.b = 0;
  this.c = 0;
  // Reset index counter for output
  this.index = 0;
  this.keyStream = new Array(this.stateArraySize << 2); // results expanded into bytes
  this.workingKey = [];

  // Set key
  this.workingKey = key;
  
  // Set up variables
  var i = 0, j = 0, k = 0;
  for(var i = 0; i < this.stateArraySize; i++) {
    this.engineState[i] = this.results[i] = 0;
  }

  // Convert the key bytes to ints and put them into results[] for initialization
  var t = new Array(key.length + (key.length & 3));
  util.copy(t, 0, key, 0, key.length);
  for(var i = 0; i < t.length; i += 4) {
    this.results[i >> 2] = util.decodeUInt32(t, i);
  }
  
  var abcdefgh = new Array(this.sizeL);
  for(var i = 0; i < abcdefgh.length; i++) abcdefgh[i] = 0;
  for(var i = 0; i < this.sizeL; i++) {
    abcdefgh[i] = 0x9e3779b9; // Phi (golden ratio)
  }
  
  for(var i = 0; i < 4; i++) {
    mix(abcdefgh);
  }
  
  for(var i = 0; i < 2; i++) {
    for(var j = 0; j < this.stateArraySize; j += this.sizeL) {
      for(var k = 0; k < this.sizeL; k++) {
        abcdefgh[k] += (i < 1) ? this.results[j + k] : this.engineState[j + k];
      }

      mix(abcdefgh);
      
      for(var k = 0; k < this.sizeL; k++) {
        this.engineState[j + k] = abcdefgh[k];
      }
    }
  }
  
  this.isaac();    
}

ISAAC.prototype.isaac = function() {
  var i = 0, x = 0, y = 0;
  
  this.b += ++this.c;
  for (i = 0; i < this.stateArraySize; i++) {
    x = this.engineState[i];
    switch (i & 3) {
        case 0: this.a ^= (this.a <<  13); break;
        case 1: this.a ^= (this.a >>>  6); break;
        case 2: this.a ^= (this.a <<   2); break;
        case 3: this.a ^= (this.a >>> 16); break;
    }
    this.a += this.engineState[(i+128) & 0xFF];
    this.engineState[i] = y = this.engineState[(x >>> 2) & 0xFF] + this.a + this.b;
    this.results[i] = this.b = this.engineState[(y >>> 10) & 0xFF] + x;
  }    
}

var mix = function(x) {
  x[0] ^= x[1]<< 11; x[3] +=x [0]; x[1] += x[2];
  x[1] ^= x[2]>>> 2; x[4] += x[1]; x[2] += x[3];
  x[2] ^= x[3]<< 8; x[5] += x[2]; x[3] += x[4];
  x[3] ^= x[4]>>>16; x[6] += x[3]; x[4] += x[5];
  x[4] ^= x[5]<< 10; x[7] += x[4]; x[5] += x[6];
  x[5] ^= x[6]>>> 4; x[0] += x[5]; x[6] += x[7];
  x[6] ^= x[7]<< 8; x[1] += x[6]; x[7] += x[0];
  x[7] ^= x[0]>>> 9; x[2] += x[7]; x[0] += x[1];
}

ISAAC.prototype.processBytes = function(src, index) {
  index = index == null ? 0 : index;
  var self = this;
  
  for(var i = 0; i < src.length; i++) {
    if(this.index == 0) {
      this.isaac();  
      this.keyStream = intToByteLittle(this.results);      
    }

    src[i] = this.keyStream[this.index] ^ src[i];
    this.index = (this.index + 1) & 1023;
  }
  
  // Return encrypted buffer
  return src;
}

ISAAC.prototype.returnByte = function(input) {
  if(this.index == 0) {
    this.isaac();  
    this.keyStream = intToByteLittle(this.results);      
  }

  input = this.keyStream[this.index] ^ input;
  this.index = (this.index + 1) & 1023;  
  return input;
}

var intToByteLittle = function(x) {
  var out = new Array(4 * x.length);
  
  for (var i = 0, j = 0; i < x.length; i++, j += 4) {
    util.copy(out, j, util.encodeUInt32(x[i]), 0, 4);
  }
  return out;
}
