var debug = require('sys').debug,
  inspect = require('sys').inspect,
  Random = require('prng/random').Random;
  
var ZeroBytePadding = exports.ZeroBytePadding = function() {  
}

ZeroBytePadding.prototype.init = function(random) {
  this.random = random != null ? random : new Random();  
}

ZeroBytePadding.prototype.getPaddingName = function() {
  return "ZeroByte";
}

ZeroBytePadding.prototype.addPadding = function(input, inOff) {
  var added = input.length - inOff;
  
  while(inOff < input.length) {
    input[inOff] = 0;
    inOff++;
  }
  
  return added;
}

ZeroBytePadding.prototype.padCount = function(input) {
  var count = input.length;
  
  while(count > 0) {
    if(input[count - 1] != 0) break;
    count--;
  }
  
  return input.length - count;
}
