var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  Long = require('long').Long;

var longZeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = Long.ZERO;
  return a;
}

var zeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

const blockLengths = {};
blockLengths["GOST3411"] = 32;
blockLengths["MD2"] = 16;
blockLengths["MD4"] = 64;
blockLengths["MD5"] = 64;

blockLengths["RIPEMD128"] = 64;
blockLengths["RIPEMD160"] = 64;

blockLengths["SHA-1"] = 64;
blockLengths["SHA-224"] = 64;
blockLengths["SHA-256"] = 64;
blockLengths["SHA-384"] = 128;
blockLengths["SHA-512"] = 128;

blockLengths["Tiger"] = 64;
blockLengths["Whirlpool"] = 64;

const IPAD = 0x36;
const OPAD = 0x5c;

var getByteLength = function(digest) {
  
}

var HMac = exports.HMac = function(digest, byteLength) {
  this.digest = digest;
  this.digestSize = digest.digestSize();
  this.blockLength = byteLength != null ? byteLength : getByteLength(digest);
  
  this.inputPad = zeroedArray(this.blockLength);
  this.outputPad = zeroedArray(this.blockLength);
}

// //
// // Update by bits
// HMac.prototype.updateBits = function(src, len) {
//   return this.skein.updateBits(src, len);
// }

//
// Common to all digests
HMac.prototype.update = function(src, len) {
}

//
// Common to all digests
HMac.prototype.reset = function() {
}

//
// Common to all digests
HMac.prototype.digest = function(encoding) {
  this.reset();
  
  // Return based on encoding
  if(encoding == null || encoding === 'binary') {
    return util.arrayToBinaryString(output);
  } else if(encoding === 'hex') {
    return util.toHex(output);
  } else if(encoding === 'array'){
    return output ;    
  }
}
