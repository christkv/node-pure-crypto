var debug = require('sys').debug,
  inspect = require('sys').inspect,
  inherits = require('sys').inherits,  
  util = require('utils'),
  Salsa20 = require('./salsa20').Salsa20;

var XSalsa20 = exports.XSalsa20 = function() {
}

XSalsa20.prototype.init = function(forEncryption, key, iv, rounds) {
  this.rounds = rounds == null ? 20 : rounds;
  this.r = null;
  if(key.length != 16 && key.length != 32) throw "Illegal keysize";
  if(iv.length != 24) throw "Illegal iv size";
  if(key.length == 16) key = key + key;
  
  var i = this.i = new Array(16);  
  var m = this.m = new Array(8);  
  for(var j = 0; j < 16; j++) i[j] = 0;
  
  // Current crypto state
  this.state = new Array(16);
  
  // Internal state index
  this.index = 0;
  this.arrayIndex = 0;
  this.inArrayIndex = 0;
  
  // Set up i
  i[0] = 0x61707865;
  i[1] = 0x3320646e;
  i[2] = 0x79622d32;
  i[3] = 0x6b206574;
  
  var numberOfWords = key.length/4;
  var keyLength = key.length;
  
  // Setup the key
  m[0] = util.decodeUInt32R(key, 0);
  m[1] = util.decodeUInt32R(key, 4);
  m[2] = util.decodeUInt32R(key, 8);
  m[3] = util.decodeUInt32R(key, 12);
  m[4] = util.decodeUInt32R(key, 16);
  m[5] = util.decodeUInt32R(key, 20);
  m[6] = util.decodeUInt32R(key, 24);
  m[7] = util.decodeUInt32R(key, 28);

  // Let's mix up the key 
  var o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o12, o13, o14, o15;
  o14 = util.decodeUInt32R(iv, 0);
  o11 = util.decodeUInt32R(iv, 4);
  o8 = util.decodeUInt32R(iv, 8);
  o5 = util.decodeUInt32R(iv, 12);
  i[14] = util.decodeUInt32R(iv, 16);
  i[11] = util.decodeUInt32R(iv, 20);

  o13 = m[0], o10 = m[1], o7 = m[2], o4 = m[3];
  o15 = m[4], o12 = m[5], o9 = m[6], o6 = m[7];
  o0 = i[0], o1 = i[1], o2 = i[2], o3 = i[3];
  
  for(var ij = this.rounds; ij > 0; ij -= 2) {    
    var r = quarter_round(o0, o4, o8, o12);
    o0 = r[0], o4 = r[1], o8 = r[2], o12 = r[3];

    r = quarter_round(o1, o5, o9, o13);
    o1 = r[0], o5 = r[1], o9 = r[2], o13 = r[3];

    r = quarter_round(o2, o6, o10, o14);
    o2 = r[0], o6 = r[1], o10 = r[2], o14 = r[3];

    r = quarter_round(o3, o7, o11, o15);
    o3 = r[0], o7 = r[1], o11 = r[2], o15 = r[3];

    r = quarter_round(o0, o13, o10, o7);
    o0 = r[0], o13 = r[1], o10 = r[2], o7 = r[3];

    r = quarter_round(o1, o14, o11, o4);
    o1 = r[0], o14 = r[1], o11 = r[2], o4 = r[3];

    r = quarter_round(o2, o15, o8, o5);
    o2 = r[0], o15 = r[1], o8 = r[2], o5 = r[3];

    r = quarter_round(o3, o12, o9, o6);
    o3 = r[0], o12 = r[1], o9 = r[2], o6 = r[3];
  }

  i[13] = o0, i[10] = o1, i[7] = o2, i[4] = o3;
  i[15] = o14, i[12] = o11, i[9] = o8, i[6] = o5;
  i[8] = i[5] = 0;  
}

XSalsa20.prototype.getAlgorithmName = function() {
  return "XSALSA20";
}

XSalsa20.prototype.reset = function() {  
}

XSalsa20.prototype.returnByte = function(input) {
  var self = this;
  
  // If we reach the 64 byte limit let's adjust the key again
  if(this.index % 64 == 0) {
    var key = self.i;
    // Unpack the key
    var o0 = key[0], o1 = key[1], o2 = key[2], o3 = key[3];
    var o4 = key[4], o5 = key[5], o6 = key[6], o7 = key[7];
    var o8 = key[8], o9 = key[9], o10 = key[10], o11 = key[11];
    var o12 = key[12], o13 = key[13], o14 = key[14], o15 = key[15];
    
    for(var ij = this.rounds; ij > 0; ij -= 2) {    
      var r = quarter_round(o0, o4, o8, o12);
      o0 = r[0], o4 = r[1], o8 = r[2], o12 = r[3];

      r = quarter_round(o1, o5, o9, o13);
      o1 = r[0], o5 = r[1], o9 = r[2], o13 = r[3];

      r = quarter_round(o2, o6, o10, o14);
      o2 = r[0], o6 = r[1], o10 = r[2], o14 = r[3];

      r = quarter_round(o3, o7, o11, o15);
      o3 = r[0], o7 = r[1], o11 = r[2], o15 = r[3];

      r = quarter_round(o0, o13, o10, o7);
      o0 = r[0], o13 = r[1], o10 = r[2], o7 = r[3];

      r = quarter_round(o1, o14, o11, o4);
      o1 = r[0], o14 = r[1], o11 = r[2], o4 = r[3];

      r = quarter_round(o2, o15, o8, o5);
      o2 = r[0], o15 = r[1], o8 = r[2], o5 = r[3];

      r = quarter_round(o3, o12, o9, o6);
      o3 = r[0], o12 = r[1], o9 = r[2], o6 = r[3];
    }

    var x0 = o0 + key[0];
    var x13 = o13 + key[13];
    var x10 = o10 + key[10];
    var x7 = o7 + key[7];

    var x4 = o4 + key[4];
    var x1 = o1 + key[1];
    var x14 = o14 + key[14];
    var x11= o11 + key[11];

    var x8 = o8 + key[8];
    var x5 = o5 + key[5];
    var x2 = o2 + key[2];
    var x15 = o15 + key[15];

    var x12 = o12 + key[12];
    var x9 = o9 + key[9];
    var x6 = o6 + key[6];
    var x3 = o3 + key[3];

    // Safe the state
    self.state = [util.encodeUInt32(x0).reverse(), 
          util.encodeUInt32(x13).reverse(), 
          util.encodeUInt32(x10).reverse(), 
          util.encodeUInt32(x7).reverse(), 
          util.encodeUInt32(x4).reverse(), 
          util.encodeUInt32(x1).reverse(), 
          util.encodeUInt32(x14).reverse(), 
          util.encodeUInt32(x11).reverse(), 
          util.encodeUInt32(x8).reverse(), 
          util.encodeUInt32(x5).reverse(), 
          util.encodeUInt32(x2).reverse(), 
          util.encodeUInt32(x15).reverse(), 
          util.encodeUInt32(x12).reverse(), 
          util.encodeUInt32(x9).reverse(), 
          util.encodeUInt32(x6).reverse(), 
          util.encodeUInt32(x3).reverse()];
    // Set up indexes
    self.arrayIndex = 0;
    self.inArrayIndex = 0;
    
    // Adjust m
    if(++key[8] == 0) {
      ++key[5];
    }    
  }   

  // Xor the stream input
  var value = input ^ self.state[self.arrayIndex][self.inArrayIndex];
  self.inArrayIndex = self.inArrayIndex + 1;
  if(self.inArrayIndex == 4) self.arrayIndex++, self.inArrayIndex = 0;
  // Update internal index
  self.index = self.index + 1;
  // Return value
  return value;
}

XSalsa20.prototype.processBytes = function(src, index) {
  index = index == null ? 0 : index;
  // Process all the bytes
  for(var i = index; i < src.length; i++) {
    src[i] = this.returnByte(src[i]);
  }
}

var encodeStream = function(src, i, value) {
  var bytes = util.encodeUInt32(value).reverse();
  if((i + 0) >= src.length) return;
  src[i + 0] = src[i + 0] ^ bytes[0];

  if((i + 1) >= src.length) return;
  src[i + 1] = src[i + 1] ^ bytes[1];

  if((i + 2) >= src.length) return;
  src[i + 2] = src[i + 2] ^ bytes[2];

  if((i + 3) >= src.length) return;
  src[i + 3] = src[i + 3] ^ bytes[3];
  return;
}

var quarter_round = function(a, b, c, d) {
  b = b ^ util.rotl(a + d, 7);
  c = c ^ util.rotl(b + a, 9);
  d = d ^ util.rotl(c + b, 13);
  a = a ^ util.rotl(d + c, 18);
  return [a, b, c, d];
}