var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  Long = require('long').Long,
  Skein = require('hash/skein').Skein;

var longZeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = Long.ZERO;
  return a;
}

var SkeinMac = exports.SkeinMac = function(stateSize, outputSize, key) {
  this.skein = new Skein(stateSize, outputSize, 0, key);
  this.xSave = this.skein.getState();
}

SkeinMac.prototype.macSize = function() {
  return this.skein.digestSize();
}

//
// Update by bits
SkeinMac.prototype.updateBits = function(src, len) {
  return this.skein.updateBits(src, len);
}

//
// Common to all digests
SkeinMac.prototype.update = function(src, len) {
  return this.skein.update(src, len);
}

//
// Common to all digests
SkeinMac.prototype.reset = function() {
  this.skein.initializeState(this.xSave);
}

//
// Common to all digests
SkeinMac.prototype.digest = function(encoding) {
  var output = this.skein.digest(encoding);
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
