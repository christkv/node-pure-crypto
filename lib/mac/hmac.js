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
  if(digest["getByteLength"] != null) {
    return digest.byteLength();
  } 
  
  var b = blockLengths[digest.algorithmName()];
  if(b == null) throw "unknown digest passed: " + digest.algorithmName();
  return b;
}

var HMac = exports.HMac = function(digest, key, byteLength) {
  this.key = key.slice(0);
  this.digestObject = digest;
  this.digesSize = digest.digestSize();
  this.blockLength = byteLength != null ? byteLength : getByteLength(digest);
  
  this.inputPad = zeroedArray(this.blockLength);
  this.outputPad = zeroedArray(this.blockLength);
  
  // Reset digest
  digest.reset();
  
  // debug("==================================== key")
  // debug(this.key)  
  
  if(key.length > this.blockLength) {
    digest.update(key);
    var output = digest.digest('array');
    util.copy(this.inputPad, 0, output, 0, output.length);
    
    for(var i = this.digestSize; i < this.inputPad.length; i++) {
      this.inputPad[i] = 0;
    }
  } else {
    util.copy(this.inputPad, 0, this.key, 0, this.key.length);

    // debug("==================================== inputpad")
    // debug(this.inputPad)    
    // debug("==================================== key")
    // debug(this.key)  
    
    for(var i = this.key.length; i < this.inputPad.length; i++) {
      this.inputPad[i] = 0;
    }
  }
  
  this.outputPad = this.inputPad.slice(0);
  
  for(var i = 0; i < this.inputPad.length; i++) {
    this.inputPad[i] = this.inputPad[i] ^ IPAD;
  }
  
  for(var i = 0; i < this.outputPad.length; i++) {
    this.outputPad[i] = this.outputPad[i] ^ OPAD;
  }
  
  // debug("==================================== inputpad")
  // debug(this.inputPad)
  // debug("==================================== outputPad")
  // debug(this.outputPad)
  
  this.digestObject.update(this.inputPad);
}

HMac.prototype.macSize = function() {
  return this.digestObjectSize;
}

//
// Common to all digests
HMac.prototype.update = function(src, len) {
  this.digestObject.update(src);
}

//
// Common to all digests
HMac.prototype.reset = function() {
  this.digestObject.reset();
  this.digestObject.update(this.inputPad);
}

//
// Common to all digests
HMac.prototype.digest = function(encoding) {
  var tmp = this.digestObject.digest('array');
  this.digestObject.update(this.outputPad);
  this.digestObject.update(tmp);
  var output = this.digestObject.digest(encoding);
  // Reset digest
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
