var debug = require('sys').debug,
  inspect = require('sys').inspect;

var ISO7816d4Padding = exports.ISO7816d4Padding = function() {  
}

ISO7816d4Padding.prototype.init = function(random) {  
}

ISO7816d4Padding.prototype.getPaddingName = function() {
  return "ISO7816-4";
}

ISO7816d4Padding.prototype.addPadding = function(input, inOff) {
  var added = (input.length - inOff);
  input[inOff] = 0x80;
  inOff++;
  
  while(inOff < input.length) {
    input[inOff] = 0;
    inOff++;
  }
  
  return added;
}

ISO7816d4Padding.prototype.padCount = function(input) {
  var count = input.length - 1;
  while(count > 0 && input[count] == 0) {
    count--;
  }
  
  if(input[count] != 0x80) {
    throw new Error("pad block corrupted");
  }
  
  return input.length - count;
}