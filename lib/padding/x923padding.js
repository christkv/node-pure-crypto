var debug = require('sys').debug,
  inspect = require('sys').inspect,
  Random = require('prng/random').Random;

var X923Padding = exports.X923Padding = function() {
}

X923Padding.prototype.init = function(random) {
  this.random = random != null ? random : new Random();    
}

X923Padding.prototype.getPaddingName = function() {
  return "X9.23";
}

X923Padding.prototype.addPadding = function(input, inOff) {
  var code = (input.length - inOff) & 0xff;
  
  while(inOff < input.length - 1) {
    if(this.random == null) {
      input[inOff] = 0;
    } else {
      input[inOff] = this.random.nextInt() & 0xff;
    }
    
    inOff++;
  } 
  
  input[inOff] = code;
  return code;
}

X923Padding.prototype.padCount = function(input) {
  var count = input[input.length - 1] & 0xff;
  
  if(count > input.length) throw new Error("pad block corrupted");
  return count;
}