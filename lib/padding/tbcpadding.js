var debug = require('sys').debug,
  inspect = require('sys').inspect;

var TBCPadding = exports.TBCPadding = function() {  
}

TBCPadding.prototype.init = function() {  
}

TBCPadding.prototype.getPaddingName = function() {
  return "TBC";
}

TBCPadding.prototype.addPadding = function(input, inOff) {
  var count = input.length - inOff;
  var code = 0;
  
  if(inOff > 0) {
    code = ((input[inOff - 1] & 0x01) == 0 ? 0xff : 0x00) & 0xff;
  } else {
    code = ((input[input.length - 1] & 0x01) == 0 ? 0xff : 0x00) & 0xff;
  }
  
  while(inOff < input.length) {
    input[inOff] = code;
    inOff++
  }
  
  return count;
}

TBCPadding.prototype.padCount = function(input) {
  var code = input[input.length - 1] & 0xff;
  var index = input.length - 1;
  
  while(index > 0 && input[index - 1] == code) {
    index--;
  }
  
  return input.length - index;
}