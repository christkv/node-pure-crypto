var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

var f1 = function(x) {
  return Long.fromNumber(util.rotr(x, 7) ^ util.rotr(x, 18) ^ (x >>> 3)).getLowBitsUnsigned();
}

var f2 = function(x) {
  return Long.fromNumber(util.rotr(x, 17) ^ util.rotr(x, 19) ^ (x >>> 10)).getLowBitsUnsigned();
}

var mod512 = function(x) {
  return x & 0x1ff;
}

var mod1024 = function(x) {
  return x & 0x3ff;
}

var dim = function(x, y) {
  return mod512(Long.fromNumber(x - y).getLowBitsUnsigned());
}

var g1 = function(x, y, z) {
  return Long.fromNumber((util.rotr(x, 10) ^ util.rotr(z, 23)) + util.rotr(y, 8)).getLowBitsUnsigned();
}

var g2 = function(x, y, z) {
  return Long.fromNumber((util.rotl(x, 10) ^ util.rotl(z, 23)) + util.rotl(y, 8)).getLowBitsUnsigned();
}

var HC128 = exports.HC128 = function() {
}

HC128.prototype.init = function(forEncryption, key, iv) {
  // Store values
  this.key = key;
  this.iv = iv;
  this.cnt = 0;
  this.idx = 0;
  this.buf = [];
  var p = this.p = new Array(512);
  var q = this.q = new Array(512);
  
  // set up key
  var w = new Array(1280);
  for(var i = 0; i < 1280; i++) w[i] = 0;
  for(var i = 0; i < 16; i++) {
    w[i >> 2] = Long.fromNumber(w[i >> 2] | ((key[i] & 0xff) << (8 * (i & 0x3)))).getLowBitsUnsigned();
  } 
  // Copy data
  util.copy(w, 4, w, 0, 4);
  
  for(var i = 0; i < iv.length && i < 16; i++) {
    w[(i >> 2) + 8] = Long.fromNumber(w[(i >> 2) + 8] | ((iv[i] & 0xff) << (8 * (i & 0x3)))).getLowBitsUnsigned();
  }
  
  // Copy data
  util.copy(w, 12, w, 8, 4);
  
  for(var i = 16; i < 1280; i++) {
    w[i] = Long.fromNumber(f2(w[i - 2]) + w[i - 7] + f1(w[i - 15]) + w[i - 16] + i).getLowBitsUnsigned();
  }

  // Copy data
  util.copy(p, 0, w, 256, 512);
  util.copy(q, 0, w, 768, 512);  
  
  for(var i = 0; i < 512; i++) {
    p[i] = this.step();
  }

  for(var i = 0; i < 512; i++) {
    q[i] = this.step();
  }
  
  this.cnt = 0;  
}

HC128.prototype.h1 = function(x) {
  return Long.fromNumber(this.q[x & 0xff] + this.q[((x >> 16) & 0xff) + 256]).getLowBitsUnsigned();
}

HC128.prototype.h2 = function(x) {
  return Long.fromNumber(this.p[x & 0xff] + this.p[((x >> 16) & 0xff) + 256]).getLowBitsUnsigned();
}

HC128.prototype.getAlgorithmName = function() {
  return "HC128";
}

HC128.prototype.reset = function() {  
}

HC128.prototype.step = function() {
  var j = mod512(this.cnt);
  var ret = 0;
  var q = this.q;
  var p = this.p;

  if(this.cnt < 512) {
    p[j] = Long.fromNumber(p[j] + g1(p[dim(j, 3)], p[dim(j, 10)], p[dim(j, 511)])).getLowBitsUnsigned();
    ret = Long.fromNumber(this.h1(p[dim(j, 12)]) ^ p[j]).getLowBitsUnsigned();
  } else {
    q[j] = Long.fromNumber(q[j] + g2(q[dim(j, 3)], q[dim(j, 10)], q[dim(j, 511)])).getLowBitsUnsigned();
    ret = Long.fromNumber(this.h2(q[dim(j, 12)]) ^ q[j]).getLowBitsUnsigned();
  }
  
  this.cnt = mod1024(this.cnt + 1);
  return ret;
}

HC128.prototype.processBytes = function(src, index, len, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;
  
  for(var i = 0; i < len; i++) {
    out[outOff + i] = src[index + i] ^ this.getByte();
  }
}

HC128.prototype.returnByte = function(input) {
  return input ^ this.getByte();
}

HC128.prototype.getByte = function() {
  if(this.idx == 0) {
    var step = this.step();
    this.buf = util.encodeUInt32R(step);    
  }
  
  var ret = this.buf[this.idx];
  this.idx = (this.idx + 1 ) & 0x3;
  return ret;
}