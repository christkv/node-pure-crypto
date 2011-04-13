var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
var tau = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574]; 

var Salsa20 = exports.Salsa20 = function(key, iv, rounds) {
  this.rounds = rounds == null ? 20 : rounds;
  this.r = null;
  if(key.length != 16 && key.length != 32) throw "Illegal keysize";
  if(iv.length != 8) throw "Illegal iv size";
  var i = this.i = new Array(16);  
  for(var j = 0; j < 16; j++) i[j] = 0;

  var numberOfWords = key.length/4;
  var keyLength = key.length;

  // Setup the key
  i[1] = util.decodeUInt32R(key, 0);
  i[2] = util.decodeUInt32R(key, 4);
  i[3] = util.decodeUInt32R(key, 8);
  i[4] = util.decodeUInt32R(key, 12);
  var ck = tau;
  if(key.length == 16) {
    i[11] = i[1]
    i[12] = i[2]
    i[13] = i[3]
    i[14] = i[4]
  } else {
    ck = sigma;
    i[11] = util.decodeUInt32R(key, 16);
    i[12] = util.decodeUInt32R(key, 20);
    i[13] = util.decodeUInt32R(key, 24);
    i[14] = util.decodeUInt32R(key, 28);
  }

  i[0] = ck[0];
  i[5] = ck[1];
  i[10] = ck[2];
  i[15] = ck[3];

  // Set up the iv
  i[6] = util.decodeUInt32R(iv, 0);
  i[7] = util.decodeUInt32R(iv, 4);
  i[8] = 0;
  i[8] = 0;    
}

Salsa20.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src, index);
}

Salsa20.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Salsa20.prototype.finalEncrypt = function() {
  return "";  
}

var quarter_round = function(a, b, c, d) {
  b = b ^ util.rotl(a + d, 7);
  c = c ^ util.rotl(b + a, 9);
  d = d ^ util.rotl(c + b, 13);
  a = a ^ util.rotl(d + c, 18);
  return [a, b, c, d];
}

var encodeStream = function(src, i, value) {
  var bytes = util.encodeUInt32R(value);
  src[i + 0] = src[i + 0] ^ bytes[0];
  src[i + 1] = src[i + 1] ^ bytes[1];
  src[i + 2] = src[i + 2] ^ bytes[2];
  src[i + 3] = src[i + 3] ^ bytes[3];
  return;
}

Salsa20.prototype.encryptStream = function(src, index) {
  var self = this;
  var l = src.length;
  if(l == 0) return [];
  var i = 0;
  var m = self.r == null ? 0 : self.r.length;
  var key = self.i;

  if(m > 0) {
    for(i = 0; i < m && i < l; i++) {
      src[i] = src[i] ^ self.r[i];
    }
    self.r = null;
  }
  
  while(i < l) {
    var o0 = key[0], o1 = key[1], o2 = key[2], o3 = key[3];
    var o4 = key[4], o5 = key[5], o6 = key[6], o7 = key[7];
    var o8 = key[8], o9 = key[9], o10 = key[10], o11 = key[11];
    var o12 = key[12], o13 = key[13], o14 = key[14], o15 = key[15];

    for(var r = self.rounds; r > 0; r -= 2) {      
      o4 = o4 ^ util.rotl(o0 + o12, 7);
      o8 = o8 ^ util.rotl(o4 + o0, 9);      
      o12 = o12 ^ util.rotl(o8 + o4, 13);      
      o0 = o0 ^ util.rotl(o12 + o8, 18);      
      o9 = o9 ^ util.rotl(o5 + o1, 7);      
      o13 = o13 ^ util.rotl(o9 + o5, 9);      
      o1 = o1 ^ util.rotl(o13 + o9, 13);      
      o5 = o5 ^ util.rotl(o1 + o13, 18);      
      o14 = o14 ^ util.rotl(o10 + o6, 7);      
      o2 = o2 ^ util.rotl(o14 + o10, 9);      
      o6 = o6 ^ util.rotl(o2 + o14, 13);      
      o10 = o10 ^ util.rotl(o6 + o2, 18);      
      o3 = o3 ^ util.rotl(o15 + o11, 7);      
      o7 = o7 ^ util.rotl(o3 + o15, 9);      
      o11 = o11 ^ util.rotl(o7 + o3, 13);      
      o15 = o15 ^ util.rotl(o11 + o7, 18);      
      o1 = o1 ^ util.rotl(o0 + o3, 7);      
      o2 = o2 ^ util.rotl(o1 + o0, 9);      
      o3 = o3 ^ util.rotl(o2 + o1, 13);      
      o0 = o0 ^ util.rotl(o3 + o2, 18);      
      o6 = o6 ^ util.rotl(o5 + o4, 7);      
      o7 = o7 ^ util.rotl(o6 + o5, 9);      
      o4 = o4 ^ util.rotl(o7 + o6, 13);      
      o5 = o5 ^ util.rotl(o4 + o7, 18);      
      o11 = o11 ^ util.rotl(o10 + o9, 7);      
      o8 = o8 ^ util.rotl(o11 + o10, 9);      
      o9 = o9 ^ util.rotl(o8 + o11, 13);      
      o10 = o10 ^ util.rotl(o9 + o8, 18);      
      o12 = o12 ^ util.rotl(o15 + o14, 7);      
      o13 = o13 ^ util.rotl(o12 + o15, 9);      
      o14 = o14 ^ util.rotl(o13 + o12, 13);      
      o15 = o15 ^ util.rotl(o14 + o13, 18);      
    } 
    
    // Mix with key
    o0 = o0 + key[0];
    o1 = o1 + key[1];
    o2 = o2 + key[2];
    o3 = o3 + key[3];
    o4 = o4 + key[4];
    o5 = o5 + key[5];
    o6 = o6 + key[6];
    o7 = o7 + key[7];
    o8 = o8 + key[8];
    o9 = o9 + key[9];
    o10 = o10 + key[10];
    o11 = o11 + key[11];
    o12 = o12 + key[12];
    o13 = o13 + key[13];
    o14 = o14 + key[14];
    o15 = o15 + key[15];    
    
    key[8] = key[8] + 1;
    if(key[8] == 0){
      key[9] = key[9] + 1;
    }
    
    var n = l - i;
    
    if(n >= 64) {
      // Xor keystream
      encodeStream(src, i, o0);
      encodeStream(src, i + 4, o1);
      encodeStream(src, i + 8, o2);
      encodeStream(src, i + 12, o3);
            
      encodeStream(src, i + 16, o4);
      encodeStream(src, i + 20, o5);
      encodeStream(src, i + 24, o6);
      encodeStream(src, i + 28, o7);
            
      encodeStream(src, i + 32, o8);
      encodeStream(src, i + 36, o9);
      encodeStream(src, i + 40, o10);
      encodeStream(src, i + 44, o11);
            
      encodeStream(src, i + 48, o12);
      encodeStream(src, i + 52, o13);
      encodeStream(src, i + 56, o14);
      encodeStream(src, i + 60, o15);      
      i += 64;
      continue;  
    }
        
    // Fill
    var j = 0;
    var b = src;
    var result = self.fillr(j, b, i, n, o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15);
    if(result.length == 0) return src;
    j = result[0], i = result[1], n = result[2];
    
    // Finish up
    for(var z = o0, f = false; j < 16; j++) {
      switch(j) {
  			case 1: z =  o1; break;
  			case 2: z =  o2; break;
  			case 3: z =  o3; break;
  			case 4: z =  o4; break;
  			case 5: z =  o5; break;
  			case 6: z =  o6; break;
  			case 7: z =  o7; break;
  			case 8: z =  o8; break;
  			case 9: z =  o9; break;
  			case 10: z = o10; break;
  			case 11: z = o11; break;
  			case 12: z = o12; break;
  			case 13: z = o13; break;
  			case 14: z = o14; break;
  			case 15: z = o15; break;    
      }

      for(var k = 0; k < 4; k++) {
        var bytes = util.encodeUInt32R(z);
        b[i] = b[i] ^ bytes[k];
        i++;

        if(f == false && i >= l) {
          l = (15 - j)*4 + (3 - k);
          if(l == 0) return src;
          self.r = new Array(l);
          for(var ij = 0; ij < l; ij++) self.r[ij] = 0;
          b = self.r;
          i = 0;
          f = true;
        }
      }
    }
  }
  
  // Return encrypted buffer
  return src;
}

Salsa20.prototype.fillr = function(j, b, i, n, o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15) {
  var self = this;
  
  for(var z = o0, y = o1; j < 16 && n >= 8; n -= 8) {
    switch(j) {
      case 2: z = o2, y = o3; break;
      case 4: z = o4, y = o5; break;
      case 6: z = o6, y = o7; break;
      case 8: z = o8, y = o9; break;
      case 10: z = o10, y = o11; break;
      case 12: z = o12, y = o13; break;
      case 14: z = o14, y = o15; break;
    }
    
    bytes = util.encodeUInt32R(z);
    b[i + 0] = b[i + 0] ^ bytes[0];
    b[i + 1] = b[i + 1] ^ bytes[1];
    b[i + 2] = b[i + 2] ^ bytes[2];
    b[i + 3] = b[i + 3] ^ bytes[3];
    bytes = util.encodeUInt32R(y);
    b[i + 4] = b[i + 4] ^ bytes[0];
    b[i + 5] = b[i + 5] ^ bytes[1];
    b[i + 6] = b[i + 6] ^ bytes[2];
    b[i + 7] = b[i + 7] ^ bytes[3];

    // Update the indexes
    i = i + 8;
    j = j + 2;
  } 
  
  if(n <= 0) {
    if(j >= 16) return [];
    n = (16 - j) * 4;
    self.r = new Array(n);
    for(var ij = 0; ij < n; ij++) self.r[ij] = 0;
    b = self.r;
    i = 0
    // Return the result
    return self.fillr(j, b, i, n, o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15);
  } 
  
  // Return status of indexes
  return [j, i, n];
}

Salsa20.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src, index);
}

Salsa20.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Salsa20.prototype.finalDecrypt = function() {
  return "";  
}
