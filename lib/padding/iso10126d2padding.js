var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  Random = require('prng/random').Random;

var ISO10126d2Padding = exports.ISO10126d2Padding = function() {  
}

ISO10126d2Padding.prototype.init = function(random) {
  this.random = random != null ? random : new Random();
}

ISO10126d2Padding.prototype.getPaddingName = function() {
  return "ISO10126-2";
}

ISO10126d2Padding.prototype.addPadding = function(input, inOff) {
  var code = (input.length - inOff) & 0xff;
  
  while(inOff < (input.length - 1)) {
    input[inOff] = this.random.nextInt() & 0xff;
    inOff++;
  }
  
  input[inOff] = code;
  return code;
}

ISO10126d2Padding.prototype.padCount = function(input) {
  var count = input[input.length - 1] & 0xff;
  
  if(count > input.length) {
    throw new Error("pad block corrupted");
  }
  
  return count;
}