var debug = require('sys').debug,
  inspect = require('sys').inspect;

var ARC4 = exports.ARC4 = function(key) {
  this.i = 0;
  this.j = 0;
  this.psize = 256;
  this.S = [];
  if(key != null) {
    this.init(key);
  }
}

ARC4.prototype.getPoolSize = function() {
  return this.psize;
}

ARC4.prototype.init = function(key) {  
  for(var i = 0; i < 256; ++i) {
    this.S[i] = i;
  }
  
  for(var i = 0, j = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    var t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  
  // Initialize pointers
  this.i = 0;
  this.j = 0;
}

ARC4.prototype.next = function() {
  var i = this.i;
  var j = this.j;
  var S = this.S;
  
  i = (i + 1) & 255;
  j = (j + S[i]) & 255;
  var t = S[i];
  S[i] = S[j];
  S[j] = t;
  return S[(t + S[i]) & 255];
}

ARC4.prototype.getBlockSize = function() {
  return 1;
}

ARC4.prototype.encrypt = function(block) {
  var i = 0;
  while(i < block.length) {
    block[i++] ^= this.next();
  }
  return block;
}

ARC4.prototype.decrypt = function(block) {
  this.encrypt(block);
}


















