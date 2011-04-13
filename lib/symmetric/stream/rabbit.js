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
  Random = require('random').Random;

// Number of encryption runs
var NUM_ROUNDS = 64;
// Random generator
var random = new Random();

var Rabbit = exports.Rabbit = function(key, iv) {
  // Create word based key
  this.key = [util.decodeUInt32(key, 0), util.decodeUInt32(key, 4), util.decodeUInt32(key, 8), util.decodeUInt32(key, 12)];
  // Create words of the iv
  this.iv = iv != null ? [util.decodeUInt32(iv, 0), util.decodeUInt32(iv, 4)] : null;  
  // Inner state
  this.x = [];
  this.c = [];
  this.b;
  this.stream = null;
}

Rabbit.prototype.encrypt = function(block, index) {
  if(index == null) index = 0;
  // Let's encrypt the content
  return this._rabbit(block, this.key, this.iv);
}

Rabbit.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  if(this.stream == null) {
    this.stream = true;
    return util.arrayToBinaryString(this._rabbit(data, this.key, this.iv));
  } else {
    return util.arrayToBinaryString(this._rabbit(data, this.key, this.iv, this.stream));    
  }
}

Rabbit.prototype.finalEncrypt = function() {
  return "";  
}

Rabbit.prototype.decrypt = function(block, index) {
  if(index == null) index = 0;
  // Let's encrypt the content
  return this._rabbit(block, this.key, this.iv);
}

Rabbit.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  if(this.stream == null) {
    this.stream = true;
    return util.arrayToBinaryString(this._rabbit(data, this.key, this.iv));
  } else {
    return util.arrayToBinaryString(this._rabbit(data, this.key, this.iv, this.stream));    
  }
}

Rabbit.prototype.finalDecrypt = function() {
  return "";  
}


// Encryption/decryption scheme
Rabbit.prototype._rabbit = function (m, k, iv, stream) {
  if(stream == null) this._keysetup(k);
  if(iv && stream == null) this._ivsetup(iv);

  for (var s = [], i = 0; i < m.length; i++) {
    if (i % 16 == 0) {
      // Iterate the system
      this._nextstate();
      // Generate 16 bytes of pseudo-random data
      s[0] = this.x[0] ^ (this.x[5] >>> 16) ^ (this.x[3] << 16);
      s[1] = this.x[2] ^ (this.x[7] >>> 16) ^ (this.x[5] << 16);
      s[2] = this.x[4] ^ (this.x[1] >>> 16) ^ (this.x[7] << 16);
      s[3] = this.x[6] ^ (this.x[3] >>> 16) ^ (this.x[1] << 16);

      // Swap endian
      for (var j = 0; j < 4; j++) {
        s[j] = ((s[j] <<  8) | (s[j] >>> 24)) & 0x00FF00FF | ((s[j] << 24) | (s[j] >>>  8)) & 0xFF00FF00;
      }

      // Convert words to bytes
      for (var b = 120; b >= 0; b -= 8) {
        s[b / 8] = (s[b >>> 5] >>> (24 - b % 32)) & 0xFF;       
      }
    }

    m[i] ^= s[i % 16];
  }
  
  return m;
}

// Key setup scheme
Rabbit.prototype._keysetup = function (k) {
  // Generate initial state values
  this.x[0] = k[0];
  this.x[2] = k[1];
  this.x[4] = k[2];
  this.x[6] = k[3];
  this.x[1] = (k[3] << 16) | (k[2] >>> 16);
  this.x[3] = (k[0] << 16) | (k[3] >>> 16);
  this.x[5] = (k[1] << 16) | (k[0] >>> 16);
  this.x[7] = (k[2] << 16) | (k[1] >>> 16);

  // Generate initial counter values
  this.c[0] = util.rotl(k[2], 16);
  this.c[2] = util.rotl(k[3], 16);
  this.c[4] = util.rotl(k[0], 16);
  this.c[6] = util.rotl(k[1], 16);
  this.c[1] = (k[0] & 0xFFFF0000) | (k[1] & 0xFFFF);
  this.c[3] = (k[1] & 0xFFFF0000) | (k[2] & 0xFFFF);
  this.c[5] = (k[2] & 0xFFFF0000) | (k[3] & 0xFFFF);
  this.c[7] = (k[3] & 0xFFFF0000) | (k[0] & 0xFFFF);

  // Clear carry bit
  this.b = 0;
  // Iterate the system four times
  for (var i = 0; i < 4; i++) this._nextstate();

  // Modify the counters
  for (var i = 0; i < 8; i++) this.c[i] ^= this.x[(i + 4) & 7];
}

// IV setup scheme
Rabbit.prototype._ivsetup = function (iv) {
  // Generate four subvectors
  var i0 = util.endian(iv[0]),
    i2 = util.endian(iv[1]),
    i1 = (i0 >>> 16) | (i2 & 0xFFFF0000),
    i3 = (i2 <<  16) | (i0 & 0x0000FFFF);

  // Modify counter values
  this.c[0] ^= i0;
  this.c[1] ^= i1;
  this.c[2] ^= i2;
  this.c[3] ^= i3;
  this.c[4] ^= i0;
  this.c[5] ^= i1;
  this.c[6] ^= i2;
  this.c[7] ^= i3;

  // Iterate the system four times
  for (var i = 0; i < 4; i++) this._nextstate();
}

// Next-state function
Rabbit.prototype._nextstate = function () {
  // Save old counter values
  for (var c_old = [], i = 0; i < 8; i++) c_old[i] = this.c[i];
  // Calculate new counter values
  this.c[0] = (this.c[0] + 0x4D34D34D + this.b) >>> 0;
  this.c[1] = (this.c[1] + 0xD34D34D3 + ((this.c[0] >>> 0) < (c_old[0] >>> 0) ? 1 : 0)) >>> 0;
  this.c[2] = (this.c[2] + 0x34D34D34 + ((this.c[1] >>> 0) < (c_old[1] >>> 0) ? 1 : 0)) >>> 0;
  this.c[3] = (this.c[3] + 0x4D34D34D + ((this.c[2] >>> 0) < (c_old[2] >>> 0) ? 1 : 0)) >>> 0;
  this.c[4] = (this.c[4] + 0xD34D34D3 + ((this.c[3] >>> 0) < (c_old[3] >>> 0) ? 1 : 0)) >>> 0;
  this.c[5] = (this.c[5] + 0x34D34D34 + ((this.c[4] >>> 0) < (c_old[4] >>> 0) ? 1 : 0)) >>> 0;
  this.c[6] = (this.c[6] + 0x4D34D34D + ((this.c[5] >>> 0) < (c_old[5] >>> 0) ? 1 : 0)) >>> 0;
  this.c[7] = (this.c[7] + 0xD34D34D3 + ((this.c[6] >>> 0) < (c_old[6] >>> 0) ? 1 : 0)) >>> 0;
  this.b = (this.c[7] >>> 0) < (c_old[7] >>> 0) ? 1 : 0;

  // Calculate the g-values
  for (var g = [], i = 0; i < 8; i++) {
    var gx = (this.x[i] + this.c[i]) >>> 0;
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
  this.x[0] = g[0] + ((g[7] << 16) | (g[7] >>> 16)) + ((g[6] << 16) | (g[6] >>> 16));
  this.x[1] = g[1] + ((g[0] <<  8) | (g[0] >>> 24)) + g[7];
  this.x[2] = g[2] + ((g[1] << 16) | (g[1] >>> 16)) + ((g[0] << 16) | (g[0] >>> 16));
  this.x[3] = g[3] + ((g[2] <<  8) | (g[2] >>> 24)) + g[1];
  this.x[4] = g[4] + ((g[3] << 16) | (g[3] >>> 16)) + ((g[2] << 16) | (g[2] >>> 16));
  this.x[5] = g[5] + ((g[4] <<  8) | (g[4] >>> 24)) + g[3];
  this.x[6] = g[6] + ((g[5] << 16) | (g[5] >>> 16)) + ((g[4] << 16) | (g[4] >>> 16));
  this.x[7] = g[7] + ((g[6] <<  8) | (g[6] >>> 24)) + g[5];
}











