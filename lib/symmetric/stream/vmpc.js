var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

var VMPC = exports.VMPC = function() {
}

VMPC.prototype.init = function(forEncryption, key, iv) {
  this.forEncryption = forEncryption
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

VMPC.prototype.getAlgorithmName = function() {
  return "VMPC";
}

VMPC.prototype.reset = function() {  
}

VMPC.prototype.returnByte = function(input) {
  var src = [input];
  // Get saved state
  var s = this.s;
  var n = this.n;
  var P = this.P;

  // Encode the byte
  s = this.s = P[(s + P[n & 0xff])  & 0xff];
  var z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
  var temp = P[n & 0xff];
  P[n & 0xff] = P[s & 0xff];
  P[s & 0xff] = temp;
  n = this.n = ((n + 1) & 0xff);        
  // xor
  input = input ^ z;
  
  // Save state of variables
  this.s = s;
  this.n = n;
  this.P = P; 
  // Return encrypted value
  return input;
}

VMPC.prototype.processBytes = function(src, index, len, out, outOFf) {
  index = index == null ? 0 : index;
  outOFf = outOFf == null ? 0 : outOFf;
  // Get saved state
  var s = this.s;
  var n = this.n;
  var P = this.P;

  // Process all the bytes
  for(var i = 0; i < len; i++) {    
    
    s = this.s = P[(s + P[n & 0xff])  & 0xff];
    var z = P[(P[(P[s & 0xff]) & 0xff] + 1) & 0xff];
    var temp = P[n & 0xff];
    P[n & 0xff] = P[s & 0xff];
    P[s & 0xff] = temp;
    n = this.n = ((n + 1) & 0xff);        
    // xor
    out[outOFf + i] = src[index + i] ^ z;
  }
  
  // Save state of variables
  this.s = s;
  this.n = n;
  this.P = P;
}
