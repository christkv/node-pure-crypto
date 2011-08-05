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
  
  var b = blockLengths[digest.getAlgorithmName()];
  if(b == null) throw "unknown digest passed: " + digest.getAlgorithmName();
  return b;
}

var HMac = exports.HMac = function(digest, byteLength) {
  if(digest != null) {
    this.digestObject = digest;
    this.digesSize = digest.getDigestSize();
    this.blockLength = byteLength != null ? byteLength : getByteLength(digest);

    this.inputPad = zeroedArray(this.blockLength);
    this.outputPad = zeroedArray(this.blockLength);
  }
}

HMac.prototype.init = function(key) {
  // Reset digest
  this.digestObject.reset();

  if(key.length > this.blockLength) {
    this.digestObject.update(key, 0, key.length);
    this.digestObject.doFinal(this.inputPad, 0);

    for(var i = this.digestSize; i < this.inputPad.length; i++) {
      this.inputPad[i] = 0;
    }
  } else {
    util.copy(this.inputPad, 0, key, 0, key.length);

    for(var i = key.length; i < this.inputPad.length; i++) {
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

  this.digestObject.update(this.inputPad, 0, this.inputPad.length);    
}

HMac.prototype.getAlgorithmName = function() {
  return this.digestObjectSize.getAlgorithmName() + "/HMAC"
}

HMac.prototype.getMacSize = function() {
  return this.digestObjectSize;
}

//
// Common to all digests
HMac.prototype.update = function(src, inOff, len) {
  this.digestObject.update(src, inOff, len);
}

//
// Common to all digests
HMac.prototype.reset = function() {
  this.digestObject.reset();
  this.digestObject.update(this.inputPad);
}

//
// Common to all digests
HMac.prototype.doFinal = function(out, outOff) {
  var tmp = new Array(this.digestSize);
  this.digestObject.doFinal(tmp, 0);
  this.digestObject.update(this.outputPad, 0, this.outputPad.length);
  this.digestObject.update(tmp, 0, tmp.length);

  var len = this.digestObject.doFinal(out, outOff);
  this.reset();
  return len;
}
