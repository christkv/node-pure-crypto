var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  Long = require('long').Long,
  Skein = require('hash/skein').Skein;

var SkeinMac = exports.SkeinMac = function() {
}

SkeinMac.prototype.init = function(stateSize, macSize, key) {
  this.skein = new Skein();
  this.skein.init(stateSize, macSize, 0, key);
  this.xSave = this.skein.getState();  
}

SkeinMac.prototype.getAlgorithmName = function() {
    return this.skein.getAlgorithmName() + "/MAC";
}

SkeinMac.prototype.getMacSize = function() {
  return this.skein.getDigestSize();
}

//
// Update by bits
SkeinMac.prototype.updateBits = function(src, inOff, len) {
  return this.skein.updateBits(src, inOff, len);
}

//
// Common to all digests
SkeinMac.prototype.update = function(src, inOff, len) {
  return this.skein.update(src, inOff, len);
}

//
// Common to all digests
SkeinMac.prototype.doFinal = function(out, outOff) {
  var output = new Array(this.skein.getDigestSize())
  var len = this.skein.doFinal(out, outOff);
  this.reset();
  return len;
}

//
// Common to all digests
SkeinMac.prototype.reset = function() {
  this.skein.initializeState(this.xSave);
}
