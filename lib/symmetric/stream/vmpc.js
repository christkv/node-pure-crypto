var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

var VMPC = exports.VMPC = function(key, iv) {
  this.key = key;
  this.iv = iv;
  // Internal variables
  var n = this.n = 0;
  var P = this.P = new Array(256);
  var s = this.s = 0;  

  // Ensure we have the correct iv length
  if(iv == null || iv.length < 1 || iv.length > 768) throw "VMPC requires 1 to 768 bytes of IV";
  // Init the key
  s = 0;

  // Initialize P  
  for(var i = 0; i < 256; i++) {
    P[i] = i;
  }
  
  for(var m = 0; m < 768; m++) {
    s = this.s = P[Long.fromNumber(s + P[m & 0xff] + key[m % key.length]).getLowBitsUnsigned() & 0xff];
    var temp = P[m & 0xff];
    P[m & 0xff] = P[s & 0xff];
    P[s & 0xff] = temp;
  }
  
  for(var m = 0; m < 768; m++) {
    s = this.s = P[Long.fromNumber(s + P[m & 0xff] + iv[m % iv.length]).getLowBitsUnsigned() & 0xff];
    var temp = P[m & 0xff];
    P[m & 0xff] = P[s & 0xff];
    P[s & 0xff] = temp;
  }  
  this.n = 0;
}

VMPC.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src);
}

VMPC.prototype.updateEncrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

VMPC.prototype.finalEncrypt = function() {
  return "";  
}

VMPC.prototype.encryptStream = function(src) {
  var s = this.s;
  var n = this.n;
  var P = this.P;
  
  for(var i = 0; i < src.length; i++) {    
    s = this.s = P[(s + P[n & 0xff])  & 0xff];
    var z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
    var temp = P[n & 0xff];
    P[n & 0xff] = P[s & 0xff];
    P[s & 0xff] = temp;
    n = this.n = ((n + 1) & 0xff);        
    // xor
    src[i] = src[i] ^ z;
  }
  
  // Return encrypted buffer
  return src;
}

VMPC.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptStream(src);
}

VMPC.prototype.updateDecrypt = function(src) {
  var data = !Array.isArray(src) ? util.binaryStringToArray(src) : src;
  return util.arrayToBinaryString(this.encryptStream(data));
}

VMPC.prototype.finalDecrypt = function() {
  return "";  
}