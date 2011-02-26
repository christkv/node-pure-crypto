var debug = require('sys').debug,
  inspect = require('sys').inspect;

var ARC4 = exports.ARC4 = function(key) {
  this.state = [];
  this.index1 = [];
  this.index2 = [];
  
  if(key != null) {
    this.setKey(key);
  }
}

ARC4.prototype.setKey = function(key) {
  var state = this.state;
  for(var i = 0; i < 256; ++i) {
    state[i] = i;
  }
  
  var j = 0;
  for(var i = 0; i < 256; ++i) {
    j = (j + state[i] + key[i % key.length]) & 255;
    var tmp = state[i];
    state[i] = state[j];
    state[j] = tmp;
  }
  
  this.index1 = 0;
  this.index2 = 0;
}

ARC4.prototype.encrypt = function(block) {
  return this.crypt(block);
}

ARC4.prototype.decrypt = function(block) {
  return this.crypt(block);
}

ARC4.prototype.getBlockSize = function() {
  return 1;
}

ARC4.prototype.getPoolSize = function() {
  return 256;
}

ARC4.prototype.next = function() {
  var i = this.index1;
  var j = this.index2;
  var state = this.state;
  
  i = (i + 1) & 255;
  j = (j + state[i]) & 255;
  var t = state[i];
  state[i] = state[j];
  state[j] = t;
  return state[(t + state[i]) & 255];
}

ARC4.prototype.crypt = function(data) {
  var i = this.index1;
  var j = this.index2;
  var state = this.state;
  
  for(var n = 0; n < data.length; ++n) {
    i = (i + 1) & 255;
    j = (j + state[i]) & 255;
    
    var tmp = state[i];
    state[i] = state[j];
    state[j] = tmp;
    
    data[n] ^= state[(state[i] + state[j]) & 255];
  }
  
  this.index1 = i;
  this.index2 = j;
  return data;
}










