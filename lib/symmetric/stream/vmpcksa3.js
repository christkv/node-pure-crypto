var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  inherits = require('sys').inherits,  
  VMPC = require('./vmpc').VMPC;
  Long = require('long').Long;

var VMPCKSA3 = exports.VMPCKSA3 = function(key, iv) {
}

inherits(VMPCKSA3, VMPC);

VMPC.prototype.init = function(forEncryption, key, iv) {
  this.key = key;
  this.iv = iv;
  // Internal variables
  var n = this.n = 0;
  var P = this.P = new Array(256);
  var s = this.s = 0;  

  // Ensure we have the correct iv length
  if(iv == null || iv.length < 1 || iv.length > 768) throw "VMPCKSA3 requires 1 to 768 bytes of IV";
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

  for(var m = 0; m < 768; m++) {
    s = this.s = P[Long.fromNumber(s + P[m & 0xff] + key[m % key.length]).getLowBitsUnsigned() & 0xff];
    var temp = P[m & 0xff];
    P[m & 0xff] = P[s & 0xff];
    P[s & 0xff] = temp;
  }

  this.n = 0;  
}
