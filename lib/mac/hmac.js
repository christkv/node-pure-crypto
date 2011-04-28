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

var HMac = exports.HMac = function(digest, byteLength) {
  this.digest = digest;
  this.digestSize = digest.
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
