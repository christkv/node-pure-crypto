//  AESKey
//  Derived from:
//    as3crypto http://code.google.com/p/as3crypto/ by Henri Torgemane
//    A public domain implementation from Karl Malbrain, malbrain@yahoo.com
//    (http://www.geocities.com/malbrain/aestable_c.html)
//  See LICENSE.txt for full license information.
var debug = require('sys').debug,
  inspect = require('sys').inspect,
  assert = require('assert'),
  util = require('utils'),
  Random = require('prng/random').Random;

// Number of encryption runs
var NUM_ROUNDS = 64;
// Random generator
var random = new Random();

var Rabbit = exports.Rabbit = function() {
}

Rabbit.prototype.init = function(forEncryption, key, iv) {
  this.forEncryption = forEncryption;
  // Create word based key
  this.keyBytes = key;
  this.ivBytes = iv;
  this.key = [util.decodeUInt32(key, 0), util.decodeUInt32(key, 4), util.decodeUInt32(key, 8), util.decodeUInt32(key, 12)];
  // Create words of the iv
  this.iv = iv != null ? [util.decodeUInt32(iv, 0), util.decodeUInt32(iv, 4)] : null;  
  // Inner state
  this.x = [];
  this.c = [];
  this.b;
  this.stream = null;
  // Stream box
  this.s = [];
  this.sPosition = 0;
  // Current stream position
  this.position = 0;   
  // Set up key and iv
  _keysetup(this, this.key);
  if(this.iv) _ivsetup(this, this.iv);  
}

Rabbit.prototype.getAlgorithmName = function() {
  return "RABBIT";
}

Rabbit.prototype.reset = function() {  
  this.init(this.forEncryption, this.keyBytes, this.ivBytes);
}

Rabbit.prototype.processBytes = function(input, inOff) {
  inOff = inOff == null ? 0 : inOff;
  // Encrypt data
  _rabbit(this, input, inOff);
}

Rabbit.prototype.returnByte = function(value) {
  return _rabbit(this, [value], 0)[0];
}

// Encryption/decryption scheme
var _rabbit = function(self, m, index) {
  for(var i = 0; i < m.length; i++, self.sPosition++) {
    // Get stream box
    var s = self.s;
    
    // If we finished the stream box, generate a new
    if(self.sPosition % 16 == 0) {
      // Iterate the system
      _nextstate(self);
      // Generate 16 bytes of pseudo-random data
      s[0] = self.x[0] ^ (self.x[5] >>> 16) ^ (self.x[3] << 16);
      s[1] = self.x[2] ^ (self.x[7] >>> 16) ^ (self.x[5] << 16);
      s[2] = self.x[4] ^ (self.x[1] >>> 16) ^ (self.x[7] << 16);
      s[3] = self.x[6] ^ (self.x[3] >>> 16) ^ (self.x[1] << 16);
      // Keep s state
      self.s = s;
      // Reset position in box
      self.sPosition = 0;      
      // Swap endian
      for (var j = 0; j < 4; j++) {
        s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF | ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
      }

      // Convert words to bytes
      for (var b = 120; b >= 0; b -= 8) {
        s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;       
      }
    }
    
    m[index + i] ^= s[self.sPosition % 16];    
  }
  
  return m;
  
  // for (var s = [], i = 0; i < m.length; i++, self.position++) {    
  //   if(self.position % 16 == 0) {
  //     // Iterate the system
  //     _nextstate(self);
  //     // Generate 16 bytes of pseudo-random data
  //     s[0] = self.x[0] ^ (self.x[5] >>> 16) ^ (self.x[3] << 16);
  //     s[1] = self.x[2] ^ (self.x[7] >>> 16) ^ (self.x[5] << 16);
  //     s[2] = self.x[4] ^ (self.x[1] >>> 16) ^ (self.x[7] << 16);
  //     s[3] = self.x[6] ^ (self.x[3] >>> 16) ^ (self.x[1] << 16);
  //     // Keep s state
  //     self.s = s;
  //     // Swap endian
  //     for (var j = 0; j < 4; j++) {
  //       s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF | ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
  //     }
  // 
  //     // Convert words to bytes
  //     for (var b = 120; b >= 0; b -= 8) {
  //       s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;       
  //     }
  //   }
  // 
  //   m[index + i] ^= s[i % 16];
  // }
  // 
  // return m;    
  // for (var s = [], i = 0; i < m.length; i++, self.position++) {    
  //   if(self.position % 16 == 0) {
  //     // Iterate the system
  //     _nextstate(self);
  //     // Generate 16 bytes of pseudo-random data
  //     s[0] = self.x[0] ^ (self.x[5] >>> 16) ^ (self.x[3] << 16);
  //     s[1] = self.x[2] ^ (self.x[7] >>> 16) ^ (self.x[5] << 16);
  //     s[2] = self.x[4] ^ (self.x[1] >>> 16) ^ (self.x[7] << 16);
  //     s[3] = self.x[6] ^ (self.x[3] >>> 16) ^ (self.x[1] << 16);
  //     // Keep s state
  //     self.s = s;
  //     // Swap endian
  //     for (var j = 0; j < 4; j++) {
  //       s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF | ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
  //     }
  // 
  //     // Convert words to bytes
  //     for (var b = 120; b >= 0; b -= 8) {
  //       s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;       
  //     }
  //   }
  // 
  //   m[index + i] ^= s[i % 16];
  // }
  // 
  // return m;
}

// Key setup scheme
var _keysetup = function(self, k) {
  // Generate initial state values
  self.x[0] = k[0];
  self.x[2] = k[1];
  self.x[4] = k[2];
  self.x[6] = k[3];
  self.x[1] = (k[3] << 16) | (k[2] >>> 16);
  self.x[3] = (k[0] << 16) | (k[3] >>> 16);
  self.x[5] = (k[1] << 16) | (k[0] >>> 16);
  self.x[7] = (k[2] << 16) | (k[1] >>> 16);

  // Generate initial counter values
  self.c[0] = util.rotl(k[2], 16);
  self.c[2] = util.rotl(k[3], 16);
  self.c[4] = util.rotl(k[0], 16);
  self.c[6] = util.rotl(k[1], 16);
  self.c[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
  self.c[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
  self.c[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
  self.c[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

  // Clear carry bit
  self.b = 0;
  // Iterate the system four times
  for (var i = 0; i < 4; i++) _nextstate(self);

  // Modify the counters
  for (var i = 0; i < 8; i++) self.c[i] ^= self.x[(i + 4) & 7];
}

// IV setup scheme
var _ivsetup = function(self, iv) {  
  // Generate four subvectors
  var i0 = util.endian(iv[0]),
    i2 = util.endian(iv[1]),
    i1 = (i0 >>> 16) | (i2 & 0xFFFF0000),
    i3 = (i2 <<  16) | (i0 & 0x0000FFFF);

  // Modify counter values
  self.c[0] ^= i0;
  self.c[1] ^= i1;
  self.c[2] ^= i2;
  self.c[3] ^= i3;
  self.c[4] ^= i0;
  self.c[5] ^= i1;
  self.c[6] ^= i2;
  self.c[7] ^= i3;

  // Iterate the system four times
  for (var i = 0; i < 4; i++) _nextstate(self);
}

// Next-state function
var _nextstate = function(self) {
  // Save old counter values
  for (var c_old = [], i = 0; i < 8; i++) c_old[i] = self.c[i];
  // Calculate new counter values
  self.c[0] = (self.c[0] + 0x4D34D34D + self.b) >>> 0;
  self.c[1] = (self.c[1] + 0xD34D34D3 + ((self.c[0] >>> 0) < (c_old[0] >>> 0) ? 1 : 0)) >>> 0;
  self.c[2] = (self.c[2] + 0x34D34D34 + ((self.c[1] >>> 0) < (c_old[1] >>> 0) ? 1 : 0)) >>> 0;
  self.c[3] = (self.c[3] + 0x4D34D34D + ((self.c[2] >>> 0) < (c_old[2] >>> 0) ? 1 : 0)) >>> 0;
  self.c[4] = (self.c[4] + 0xD34D34D3 + ((self.c[3] >>> 0) < (c_old[3] >>> 0) ? 1 : 0)) >>> 0;
  self.c[5] = (self.c[5] + 0x34D34D34 + ((self.c[4] >>> 0) < (c_old[4] >>> 0) ? 1 : 0)) >>> 0;
  self.c[6] = (self.c[6] + 0x4D34D34D + ((self.c[5] >>> 0) < (c_old[5] >>> 0) ? 1 : 0)) >>> 0;
  self.c[7] = (self.c[7] + 0xD34D34D3 + ((self.c[6] >>> 0) < (c_old[6] >>> 0) ? 1 : 0)) >>> 0;
  self.b = (self.c[7] >>> 0) < (c_old[7] >>> 0) ? 1 : 0;

  // Calculate the g-values
  for (var g = [], i = 0; i < 8; i++) {
    var gx = (self.x[i] + self.c[i]) >>> 0;
    // Construct high and low argument for squaring
    var ga = gx & 0xFFFF,
       gb = gx >>> 16;
    // Calculate high and low result of squaring
    var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb,
    gl = (((gx & 0xFFFF0000) * gx) >>> 0) + (((gx & 0x0000FFFF) * gx) >>> 0) >>> 0;
    // High XOR low
    g[i] = gh ^ gl;
  }

  // Calculate new state values
  self.x[0] = g[0] + ((g[7] << 16) | (g[7] >>> 16)) + ((g[6] << 16) | (g[6] >>> 16));
  self.x[1] = g[1] + ((g[0] <<  8) | (g[0] >>> 24)) + g[7];
  self.x[2] = g[2] + ((g[1] << 16) | (g[1] >>> 16)) + ((g[0] << 16) | (g[0] >>> 16));
  self.x[3] = g[3] + ((g[2] <<  8) | (g[2] >>> 24)) + g[1];
  self.x[4] = g[4] + ((g[3] << 16) | (g[3] >>> 16)) + ((g[2] << 16) | (g[2] >>> 16));
  self.x[5] = g[5] + ((g[4] <<  8) | (g[4] >>> 24)) + g[3];
  self.x[6] = g[6] + ((g[5] << 16) | (g[5] >>> 16)) + ((g[4] << 16) | (g[4] >>> 16));
  self.x[7] = g[7] + ((g[6] <<  8) | (g[6] >>> 24)) + g[5];
}











