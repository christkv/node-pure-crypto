var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// Seed Cipher
const BlockSize = 16;
const KeySize = 16;
const ROUNDS = 16;
const ND = 0xFFFFFFFF;
// const kInc = 2;

var Seed = exports.Seed = function() {
}

Seed.prototype.init = function(forEncryption, key) {
  if(forEncryption) {
    this.key = createKey(key);
  } else {
    this.key = createKey(key, true);
  }  
}

var createKey = function(key, decrypt) {
  var key01 = Long.fromBits(util.decodeUInt32(key, 4), util.decodeUInt32(key, 0));
  var key23 = Long.fromBits(util.decodeUInt32(key, 12), util.decodeUInt32(key, 8));
  
  // var k = this.key = new Array(32);
  var k = new Array(32);
  var index = 0; 
  var kInc = 2; 
  
  if(decrypt) {
    index = index + 30;
    kInc = 0 - kInc;
  }
  
  // Mix up the key
  for(var i = 0; i < ROUNDS; i++) {
    var t0 = Long.fromNumber(key01.shiftRightUnsigned(32).getLowBitsUnsigned()
      + key23.shiftRightUnsigned(32).getLowBitsUnsigned()
      - s_kc[i]).getLowBitsUnsigned();

    var t0 = key01.shiftRightUnsigned(32).add(key23.shiftRightUnsigned(32))
      .subtract(Long.fromNumber(s_kc[i])).getLowBitsUnsigned();
      
    var t1 = Long.fromNumber(key01.getLowBitsUnsigned() - key23.getLowBitsUnsigned() + s_kc[i]).getLowBitsUnsigned();    
    var k0 = G(t0);
    var k1 = G(t1);
    
    k[index + 0] = G(t0);
    k[index + 1] = G(t1);    
    index = index + kInc;
    
    if(i & 1) {
      key23 = int64lrot(key23, 8);
    } else {
      key01 = int64rrot(key01, 8);
    }
  }
  
  return k;  
}

function int64rrot(x, shift) {
    var l = (x.low_ >>> shift) | (x.high_ << (32-shift));
    var h = (x.high_ >>> shift) | (x.low_ << (32-shift));
    return new Long(l, h);
}

function int64lrot(x, shift) {
    var l = (x.low_ << shift) | (x.high_ >>> (32-shift));
    var h = (x.high_ << shift) | (x.low_ >>> (32-shift));
    return new Long(l, h);
}

// Block size of cipher
Seed.prototype.getBlockSize = function() { return BlockSize; }
// Algorithm Name
Seed.prototype.getAlgorithmName = function() { return "SEED"; }
// Reset cipher
Seed.prototype.reset = function() {}

// Process a block
Seed.prototype.processBlock = function(input, inOff, out, outOff) {
  inOff = inOff == null ? 0 : inOff;
  outOff = outOff == null ? 0 : outOff;
  return cryptBlock(input, this.key, inOff, out, outOff);
}

var cryptBlock = function(block, key, index, out, outOff) {
  var a0 = util.decodeUInt32(block, index);
  var a1 = util.decodeUInt32(block, index + 4);
  var b0 = util.decodeUInt32(block, index + 8);
  var b1 = util.decodeUInt32(block, index + 12);
  var t0 = 0;
  var t1 = 0;
  
  for(var i = 0; i < ROUNDS; i += 2) {
    t0 = Long.fromNumber(b0 ^ key[2*i + 0]).getLowBitsUnsigned();
    t1 = Long.fromNumber(b1 ^ key[2*i + 1] ^ t0).getLowBitsUnsigned();
    t1 = G(t1);
    t0 = Long.fromNumber(t0 + t1).getLowBitsUnsigned();
    t0 = G(t0);
    t1 = Long.fromNumber(t1 + t0).getLowBitsUnsigned();
    t1 = G(t1);
    a0 = Long.fromNumber(a0 ^ (t0 + t1)).getLowBitsUnsigned();
    a1 = Long.fromNumber(a1 ^ t1).getLowBitsUnsigned();
    
    t0 = Long.fromNumber(a0 ^ key[2*i + 2]).getLowBitsUnsigned();
    t1 = Long.fromNumber(a1 ^ key[2*i + 3] ^ t0).getLowBitsUnsigned();
    t1 = G(t1);
    t0 = Long.fromNumber(t0 + t1).getLowBitsUnsigned();
    t0 = G(t0);
    t1 = Long.fromNumber(t1 + t0).getLowBitsUnsigned();
    t1 = G(t1);
    b0 = Long.fromNumber(b0 ^ (t0 + t1)).getLowBitsUnsigned();
    b1 = Long.fromNumber(b1 ^ t1).getLowBitsUnsigned();
  }

  util.inPlaceEncodeUInt32(b0, out, outOff);
  util.inPlaceEncodeUInt32(b1, out, outOff + 4);
  util.inPlaceEncodeUInt32(a0, out, outOff + 8);
  util.inPlaceEncodeUInt32(a1, out, outOff + 12);
  return BlockSize;
}

var SS0 = function(x) {
  return Long.fromNumber((s_s0[x] * 0x01010101 & 0x3FCFF3FC)).getLowBitsUnsigned();
}

var SS1 = function(x) {
  return Long.fromNumber((s_s1[x] * 0x01010101 & 0xFC3FCFF3)).getLowBitsUnsigned();
}

var SS2 = function(x) {
  return Long.fromNumber(s_s0[x] * 0x01010101 & 0xF3FC3FCF).getLowBitsUnsigned();    
}

var SS3 = function(x) {
  return Long.fromNumber(s_s1[x] * 0x01010101 & 0xCFF3FC3F).getLowBitsUnsigned();    
}

var G = function(x) {
  // Unpack the bytes of the value
  var bytes = util.encodeUInt32(x).reverse();
  
  var ss0 = SS0(bytes[0]);
  var ss1 = SS1(bytes[1]);
  var ss2 = SS2(bytes[2]);
  var ss3 = SS3(bytes[3]);

  return Long.fromNumber(ss0)
          .xor(Long.fromNumber(ss1))
          .xor(Long.fromNumber(ss2))
          .xor(Long.fromNumber(ss3)).getLowBitsUnsigned();
}

// SBOXES
var s_kc = [
 0x9e3779b9, 0x3c6ef373, 0x78dde6e6, 0xf1bbcdcc, 0xe3779b99, 0xc6ef3733, 0x8dde6e67, 0x1bbcdccf,
 0x3779b99e, 0x6ef3733c, 0xdde6e678, 0xbbcdccf1, 0x779b99e3, 0xef3733c6, 0xde6e678d, 0xbcdccf1b];

var s_s0 = [
 0xA9, 0x85, 0xD6, 0xD3, 0x54, 0x1D, 0xAC, 0x25, 0x5D, 0x43, 0x18, 0x1E, 0x51, 0xFC, 0xCA, 0x63, 0x28,
 0x44, 0x20, 0x9D, 0xE0, 0xE2, 0xC8, 0x17, 0xA5, 0x8F, 0x03, 0x7B, 0xBB, 0x13, 0xD2, 0xEE, 0x70, 0x8C,
 0x3F, 0xA8, 0x32, 0xDD, 0xF6, 0x74, 0xEC, 0x95, 0x0B, 0x57, 0x5C, 0x5B, 0xBD, 0x01, 0x24, 0x1C, 0x73,
 0x98, 0x10, 0xCC, 0xF2, 0xD9, 0x2C, 0xE7, 0x72, 0x83, 0x9B, 0xD1, 0x86, 0xC9, 0x60, 0x50, 0xA3, 0xEB,
 0x0D, 0xB6, 0x9E, 0x4F, 0xB7, 0x5A, 0xC6, 0x78, 0xA6, 0x12, 0xAF, 0xD5, 0x61, 0xC3, 0xB4, 0x41, 0x52,
 0x7D, 0x8D, 0x08, 0x1F, 0x99, 0x00, 0x19, 0x04, 0x53, 0xF7, 0xE1, 0xFD, 0x76, 0x2F, 0x27, 0xB0, 0x8B,
 0x0E, 0xAB, 0xA2, 0x6E, 0x93, 0x4D, 0x69, 0x7C, 0x09, 0x0A, 0xBF, 0xEF, 0xF3, 0xC5, 0x87, 0x14, 0xFE,
 0x64, 0xDE, 0x2E, 0x4B, 0x1A, 0x06, 0x21, 0x6B, 0x66, 0x02, 0xF5, 0x92, 0x8A, 0x0C, 0xB3, 0x7E, 0xD0,
 0x7A, 0x47, 0x96, 0xE5, 0x26, 0x80, 0xAD, 0xDF, 0xA1, 0x30, 0x37, 0xAE, 0x36, 0x15, 0x22, 0x38, 0xF4,
 0xA7, 0x45, 0x4C, 0x81, 0xE9, 0x84, 0x97, 0x35, 0xCB, 0xCE, 0x3C, 0x71, 0x11, 0xC7, 0x89, 0x75, 0xFB,
 0xDA, 0xF8, 0x94, 0x59, 0x82, 0xC4, 0xFF, 0x49, 0x39, 0x67, 0xC0, 0xCF, 0xD7, 0xB8, 0x0F, 0x8E, 0x42,
 0x23, 0x91, 0x6C, 0xDB, 0xA4, 0x34, 0xF1, 0x48, 0xC2, 0x6F, 0x3D, 0x2D, 0x40, 0xBE, 0x3E, 0xBC, 0xC1,
 0xAA, 0xBA, 0x4E, 0x55, 0x3B, 0xDC, 0x68, 0x7F, 0x9C, 0xD8, 0x4A, 0x56, 0x77, 0xA0, 0xED, 0x46, 0xB5,
 0x2B, 0x65, 0xFA, 0xE3, 0xB9, 0xB1, 0x9F, 0x5E, 0xF9, 0xE6, 0xB2, 0x31, 0xEA, 0x6D, 0x5F, 0xE4, 0xF0,
 0xCD, 0x88, 0x16, 0x3A, 0x58, 0xD4, 0x62, 0x29, 0x07, 0x33, 0xE8, 0x1B, 0x05, 0x79, 0x90, 0x6A, 0x2A,
 0x9A];

var s_s1 = [
 0x38, 0xE8, 0x2D, 0xA6, 0xCF, 0xDE, 0xB3, 0xB8, 0xAF, 0x60, 0x55, 0xC7, 0x44, 0x6F, 0x6B, 0x5B, 0xC3,
 0x62, 0x33, 0xB5, 0x29, 0xA0, 0xE2, 0xA7, 0xD3, 0x91, 0x11, 0x06, 0x1C, 0xBC, 0x36, 0x4B, 0xEF, 0x88,
 0x6C, 0xA8, 0x17, 0xC4, 0x16, 0xF4, 0xC2, 0x45, 0xE1, 0xD6, 0x3F, 0x3D, 0x8E, 0x98, 0x28, 0x4E, 0xF6,
 0x3E, 0xA5, 0xF9, 0x0D, 0xDF, 0xD8, 0x2B, 0x66, 0x7A, 0x27, 0x2F, 0xF1, 0x72, 0x42, 0xD4, 0x41, 0xC0,
 0x73, 0x67, 0xAC, 0x8B, 0xF7, 0xAD, 0x80, 0x1F, 0xCA, 0x2C, 0xAA, 0x34, 0xD2, 0x0B, 0xEE, 0xE9, 0x5D,
 0x94, 0x18, 0xF8, 0x57, 0xAE, 0x08, 0xC5, 0x13, 0xCD, 0x86, 0xB9, 0xFF, 0x7D, 0xC1, 0x31, 0xF5, 0x8A,
 0x6A, 0xB1, 0xD1, 0x20, 0xD7, 0x02, 0x22, 0x04, 0x68, 0x71, 0x07, 0xDB, 0x9D, 0x99, 0x61, 0xBE, 0xE6,
 0x59, 0xDD, 0x51, 0x90, 0xDC, 0x9A, 0xA3, 0xAB, 0xD0, 0x81, 0x0F, 0x47, 0x1A, 0xE3, 0xEC, 0x8D, 0xBF,
 0x96, 0x7B, 0x5C, 0xA2, 0xA1, 0x63, 0x23, 0x4D, 0xC8, 0x9E, 0x9C, 0x3A, 0x0C, 0x2E, 0xBA, 0x6E, 0x9F,
 0x5A, 0xF2, 0x92, 0xF3, 0x49, 0x78, 0xCC, 0x15, 0xFB, 0x70, 0x75, 0x7F, 0x35, 0x10, 0x03, 0x64, 0x6D,
 0xC6, 0x74, 0xD5, 0xB4, 0xEA, 0x09, 0x76, 0x19, 0xFE, 0x40, 0x12, 0xE0, 0xBD, 0x05, 0xFA, 0x01, 0xF0,
 0x2A, 0x5E, 0xA9, 0x56, 0x43, 0x85, 0x14, 0x89, 0x9B, 0xB0, 0xE5, 0x48, 0x79, 0x97, 0xFC, 0x1E, 0x82,
 0x21, 0x8C, 0x1B, 0x5F, 0x77, 0x54, 0xB2, 0x1D, 0x25, 0x4F, 0x00, 0x46, 0xED, 0x58, 0x52, 0xEB, 0x7E,
 0xDA, 0xC9, 0xFD, 0x30, 0x95, 0x65, 0x3C, 0xB6, 0xE4, 0xBB, 0x7C, 0x0E, 0x50, 0x39, 0x26, 0x32, 0x84,
 0x69, 0x93, 0x37, 0xE7, 0x24, 0xA4, 0xCB, 0x53, 0x0A, 0x87, 0xD9, 0x4C, 0x83, 0x8F, 0xCE, 0x3B, 0x4A,
 0xB7];
