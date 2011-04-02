var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

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
  i[1] = Long.fromNumber(util.decodeUInt32(key.slice(0, 4).reverse(), 0)).getLowBitsUnsigned();
  i[2] = Long.fromNumber(util.decodeUInt32(key.slice(4, 8).reverse(), 0)).getLowBitsUnsigned();
  i[3] = Long.fromNumber(util.decodeUInt32(key.slice(8, 12).reverse(), 0)).getLowBitsUnsigned();
  i[4] = Long.fromNumber(util.decodeUInt32(key.slice(12, 16).reverse(), 0)).getLowBitsUnsigned();
  var ck = tau;
  if(key.length == 16) {
    i[11] = i[1]
    i[12] = i[2]
    i[13] = i[3]
    i[14] = i[4]
  } else {
    ck = sigma;
    i[11] = Long.fromNumber(util.decodeUInt32(key.slice(16, 20).reverse(), 0)).getLowBitsUnsigned();
    i[12] = Long.fromNumber(util.decodeUInt32(key.slice(20, 24).reverse(), 0)).getLowBitsUnsigned();
    i[13] = Long.fromNumber(util.decodeUInt32(key.slice(24, 28).reverse(), 0)).getLowBitsUnsigned();
    i[14] = Long.fromNumber(util.decodeUInt32(key.slice(28, 32).reverse(), 0)).getLowBitsUnsigned();
  }

  i[0] = ck[0];
  i[5] = ck[1];
  i[10] = ck[2];
  i[15] = ck[3];
  
  // Set up the iv
  i[6] = Long.fromNumber(util.decodeUInt32(iv.slice(0, 4).reverse(), 0)).getLowBitsUnsigned();
  i[7] = Long.fromNumber(util.decodeUInt32(iv.slice(4, 8).reverse(), 0)).getLowBitsUnsigned();
  i[8] = 0;
  i[8] = 0;  
}

Salsa20.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src);
}

Salsa20.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Salsa20.prototype.finalEncrypt = function() {
  return "";  
}

var quarter_round = function(a, b, c, d) {
  b = Long.fromNumber(b ^ util.rotl(a + d, 7)).getLowBitsUnsigned();
  c = Long.fromNumber(c ^ util.rotl(b + a, 9)).getLowBitsUnsigned();
  d = Long.fromNumber(d ^ util.rotl(c + b, 13)).getLowBitsUnsigned();
  a = Long.fromNumber(a ^ util.rotl(d + c, 18)).getLowBitsUnsigned();
  return [a, b, c, d];
}

var encodeStream = function(src, i, value) {
  var bytes = util.encodeUInt32(value).reverse();
  src[i + 0] = src[i + 0] ^ bytes[0];
  src[i + 1] = src[i + 1] ^ bytes[1];
  src[i + 2] = src[i + 2] ^ bytes[2];
  src[i + 3] = src[i + 3] ^ bytes[3];
  return;
}

Salsa20.prototype.encryptStream = function(src) {
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
      o4 = Long.fromNumber(o4 ^ util.rotl(o0 + o12, 7)).getLowBitsUnsigned();
      o8 = Long.fromNumber(o8 ^ util.rotl(o4 + o0, 9)).getLowBitsUnsigned();      
      o12 = Long.fromNumber(o12 ^ util.rotl(o8 + o4, 13)).getLowBitsUnsigned();      
      o0 = Long.fromNumber(o0 ^ util.rotl(o12 + o8, 18)).getLowBitsUnsigned();      
      o9 = Long.fromNumber(o9 ^ util.rotl(o5 + o1, 7)).getLowBitsUnsigned();      
      o13 = Long.fromNumber(o13 ^ util.rotl(o9 + o5, 9)).getLowBitsUnsigned();      
      o1 = Long.fromNumber(o1 ^ util.rotl(o13 + o9, 13)).getLowBitsUnsigned();      
      o5 = Long.fromNumber(o5 ^ util.rotl(o1 + o13, 18)).getLowBitsUnsigned();      
      o14 = Long.fromNumber(o14 ^ util.rotl(o10 + o6, 7)).getLowBitsUnsigned();      
      o2 = Long.fromNumber(o2 ^ util.rotl(o14 + o10, 9)).getLowBitsUnsigned();      
      o6 = Long.fromNumber(o6 ^ util.rotl(o2 + o14, 13)).getLowBitsUnsigned();      
      o10 = Long.fromNumber(o10 ^ util.rotl(o6 + o2, 18)).getLowBitsUnsigned();      
      o3 = Long.fromNumber(o3 ^ util.rotl(o15 + o11, 7)).getLowBitsUnsigned();      
      o7 = Long.fromNumber(o7 ^ util.rotl(o3 + o15, 9)).getLowBitsUnsigned();      
      o11 = Long.fromNumber(o11 ^ util.rotl(o7 + o3, 13)).getLowBitsUnsigned();      
      o15 = Long.fromNumber(o15 ^ util.rotl(o11 + o7, 18)).getLowBitsUnsigned();      
      o1 = Long.fromNumber(o1 ^ util.rotl(o0 + o3, 7)).getLowBitsUnsigned();      
      o2 = Long.fromNumber(o2 ^ util.rotl(o1 + o0, 9)).getLowBitsUnsigned();      
      o3 = Long.fromNumber(o3 ^ util.rotl(o2 + o1, 13)).getLowBitsUnsigned();      
      o0 = Long.fromNumber(o0 ^ util.rotl(o3 + o2, 18)).getLowBitsUnsigned();      
      o6 = Long.fromNumber(o6 ^ util.rotl(o5 + o4, 7)).getLowBitsUnsigned();      
      o7 = Long.fromNumber(o7 ^ util.rotl(o6 + o5, 9)).getLowBitsUnsigned();      
      o4 = Long.fromNumber(o4 ^ util.rotl(o7 + o6, 13)).getLowBitsUnsigned();      
      o5 = Long.fromNumber(o5 ^ util.rotl(o4 + o7, 18)).getLowBitsUnsigned();      
      o11 = Long.fromNumber(o11 ^ util.rotl(o10 + o9, 7)).getLowBitsUnsigned();      
      o8 = Long.fromNumber(o8 ^ util.rotl(o11 + o10, 9)).getLowBitsUnsigned();      
      o9 = Long.fromNumber(o9 ^ util.rotl(o8 + o11, 13)).getLowBitsUnsigned();      
      o10 = Long.fromNumber(o10 ^ util.rotl(o9 + o8, 18)).getLowBitsUnsigned();      
      o12 = Long.fromNumber(o12 ^ util.rotl(o15 + o14, 7)).getLowBitsUnsigned();      
      o13 = Long.fromNumber(o13 ^ util.rotl(o12 + o15, 9)).getLowBitsUnsigned();      
      o14 = Long.fromNumber(o14 ^ util.rotl(o13 + o12, 13)).getLowBitsUnsigned();      
      o15 = Long.fromNumber(o15 ^ util.rotl(o14 + o13, 18)).getLowBitsUnsigned();      
    } 
    
    // Mix with key
    o0 = Long.fromNumber(o0 + key[0]).getLowBitsUnsigned();
    o1 = Long.fromNumber(o1 + key[1]).getLowBitsUnsigned();
    o2 = Long.fromNumber(o2 + key[2]).getLowBitsUnsigned();
    o3 = Long.fromNumber(o3 + key[3]).getLowBitsUnsigned();
    o4 = Long.fromNumber(o4 + key[4]).getLowBitsUnsigned();
    o5 = Long.fromNumber(o5 + key[5]).getLowBitsUnsigned();
    o6 = Long.fromNumber(o6 + key[6]).getLowBitsUnsigned();
    o7 = Long.fromNumber(o7 + key[7]).getLowBitsUnsigned();
    o8 = Long.fromNumber(o8 + key[8]).getLowBitsUnsigned();
    o9 = Long.fromNumber(o9 + key[9]).getLowBitsUnsigned();
    o10 = Long.fromNumber(o10 + key[10]).getLowBitsUnsigned();
    o11 = Long.fromNumber(o11 + key[11]).getLowBitsUnsigned();
    o12 = Long.fromNumber(o12 + key[12]).getLowBitsUnsigned();
    o13 = Long.fromNumber(o13 + key[13]).getLowBitsUnsigned();
    o14 = Long.fromNumber(o14 + key[14]).getLowBitsUnsigned();
    o15 = Long.fromNumber(o15 + key[15]).getLowBitsUnsigned();    
    
    key[8] = Long.fromNumber(key[8] + 1).getLowBitsUnsigned();
    if(key[8] == 0){
      key[9] = Long.fromNumber(key[9] + 1).getLowBitsUnsigned();
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
        var bytes = util.encodeUInt32(z).reverse();
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
    
    bytes = util.encodeUInt32(z).reverse();
    b[i + 0] = b[i + 0] ^ bytes[0];
    b[i + 1] = b[i + 1] ^ bytes[1];
    b[i + 2] = b[i + 2] ^ bytes[2];
    b[i + 3] = b[i + 3] ^ bytes[3];
    bytes = util.encodeUInt32(y).reverse();
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
  return this.encryptStream(src);
}

Salsa20.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

Salsa20.prototype.finalDecrypt = function() {
  return "";  
}
