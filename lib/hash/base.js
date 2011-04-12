var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  util = require('utils'),
  Long = require('long').Long;

const BYTE_LENGTH = 64;

var BaseDigest = exports.BaseDigest = function() {
  // Common variables
  this.xBuf = [0, 0, 0, 0];
  this.xBufOff = 0;
  this.byteCount = Long.ZERO;  
}

//
// Common to all digests
BaseDigest.prototype.reset = function() {
  this.byteCount = Long.ZERO;
}

//
// Common to all digests
var update = function(instance, b) {
  instance.xBuf[instance.xBufOff++] = b;
  
  if(instance.xBufOff === instance.xBuf.length) {
    instance.processWord(instance.xBuf, 0);
    instance.xBufOff = 0;
  }
  
  instance.byteCount = instance.byteCount.add(Long.fromNumber(1));
}

var byteLength = function() {
  return BYTE_LENGTH;
}

//
// Common to all digests
BaseDigest.prototype.update = function(src) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var inOff = 0
  var len = src.length;
  
  //
  // fill the current word
  //
  while((this.xBufOff != 0) && (len > 0)) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }
  
  //
  // process whole words.
  //
  while(len > this.xBuf.length) {
    this.processWord(src, inOff);
    
    inOff += this.xBuf.length;
    len -= this.xBuf.length;
    this.byteCount = this.byteCount.add(Long.fromNumber(this.xBuf.length));
  }
  
  //
  // load in the remainder.
  //
  while(len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;    
  }  
}

BaseDigest.prototype.finish = function() {
  var bitLength = this.byteCount.shiftLeft(3);
  
  //
  // add the pad bytes.
  //
  update(this, 128);

  while(this.xBufOff != 0) {
    update(this, 0);
  }

  this.processLength(bitLength);
  this.processBlock();
}