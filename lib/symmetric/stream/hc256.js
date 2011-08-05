var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

var HC256 = exports.HC256 = function() {
}

HC256.prototype.init = function(forEncryption, key, iv) {
  // Store values
  this.key = key;
  this.iv = iv;
  this.cnt = 0;
  this.idx = 0;
  this.buf = [];
  var p = this.p = new Array(1024);
  var q = this.q = new Array(1024);
  
  if(key.length != 32 && key.length != 16) throw "The key must be 128/256 bits long";
  if(iv.length < 16) throw "The IV must be at least 128 bits long";
  
  if(key.length != 32) {
    key = this.key = key.concat(key);
  }

  if(iv.length < 32) {
    var newIV = new Array(32);
    util.copy(newIV, 0, iv, 0, iv.length);
    util.copy(newIV, iv.length, iv, 0, newIV.length - iv.length);
    iv = this.iv = newIV;
  }
  
  this.cnt = 0;
  // set up key
  var w = new Array(2560);
  for(var i = 0; i < 2560; i++) w[i] = 0;
  for(var i = 0; i < 32; i++) {
    w[i >> 2] = Long.fromNumber(w[i >> 2] | ((key[i] & 0xff) << (8 * (i & 0x3)))).getLowBitsUnsigned();
  } 

  for(var i = 0; i < 32; i++) {
    w[(i >> 2) + 8] = Long.fromNumber(w[(i >> 2) + 8] | ((iv[i] & 0xff) << (8 * (i & 0x3)))).getLowBitsUnsigned();
  }
  
  for(var i = 16; i < 2560; i++) {
    var x = w[i - 2];
    var y = w[i - 15];
    w[i] = Long.fromNumber((util.rotr(x, 17) ^ util.rotr(x, 19) ^ (x >>> 10))
        + w[i - 7]
        + (util.rotr(y, 7) ^ util.rotr(y, 18) ^ (y >>> 3))
        + w[i - 16] + i).getLowBitsUnsigned();
  }
  
  // Copy data
  util.copy(p, 0, w, 512, 1024);
  util.copy(q, 0, w, 1536, 1024);  
  
  for(var i = 0; i < 4096; i++) {
    this.step();
  }

  this.cnt = 0;  
}

HC256.prototype.step = function() {
  var j = this.cnt & 0x3ff;
  var ret = 0;
  var q = this.q;
  var p = this.p;  

  if(this.cnt < 1024) {
    var x = p[(j - 3 & 0x3ff)]
    var y = p[(j - 1023 & 0x3ff)]
    p[j] = Long.fromNumber(p[j] + p[j - 10 & 0x3ff]
          + (util.rotr(x, 10) ^ util.rotr(y, 23))
          + q[((x ^ y) & 0x3ff)]).getLowBitsUnsigned();
          
    x = p[(j - 12 & 0x3ff)];
    ret = Long.fromNumber((q[x & 0xff] + q[((x >> 8) & 0xff) + 256]
          + q[((x >> 16) & 0xff) + 512] + q[((x >> 24) & 0xff) + 768])
          ^ p[j]).getLowBitsUnsigned();
  } else {
    var x = q[(j - 3 & 0x3ff)]
    var y = q[(j - 1023 & 0x3ff)]
    q[j] = Long.fromNumber(q[j] + q[j - 10 & 0x3ff]
          + (util.rotr(x, 10) ^ util.rotr(y, 23))
          + p[((x ^ y) & 0x3ff)]).getLowBitsUnsigned();

    x = q[(j - 12 & 0x3ff)];
    ret = Long.fromNumber((p[x & 0xff] + p[((x >> 8) & 0xff) + 256]
          + p[((x >> 16) & 0xff) + 512] + p[((x >> 24) & 0xff) + 768])
          ^ q[j]).getLowBitsUnsigned();    
  }
  
  this.cnt = this.cnt + 1 & 0x7ff;
  return ret;
}

HC256.prototype.getAlgorithmName = function() {
  return "HC256";
}

HC256.prototype.reset = function() {  
}

HC256.prototype.processBytes = function(src, index, len, out, outOff) {
  index = index == null ? 0 : index;
  outOff = outOff == null ? 0 : outOff;

  for(var i = 0; i < len; i++) {
    var a = this.getByte()
    out[outOff + i] = src[index + i] ^ a;
  }
}

HC256.prototype.returnByte = function(input) {
  return input ^ this.getByte();
}

HC256.prototype.getByte = function() {
  if(this.idx == 0) {
    var step = this.step();
    this.buf = util.encodeUInt32(step).reverse();    
  }
  
  var ret = this.buf[this.idx];
  this.idx = (this.idx + 1 ) & 0x3;
  return ret;
}