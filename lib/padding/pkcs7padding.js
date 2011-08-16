var debug = require('sys').debug,
  inspect = require('sys').inspect;

var PKCS7Padding = exports.PKCS7Padding = function() {  
}

PKCS7Padding.prototype.init = function() {  
}

PKCS7Padding.prototype.getPaddingName = function() {
  return "PKCS7";
}

PKCS7Padding.prototype.addPadding = function(input, inOff) {
  var code = (input.length - inOff) & 0xff;
  
  while(inOff < input.length) {
    input[inOff] = code;
    inOff++;
  }
  
  return code;
}

PKCS7Padding.prototype.padCount = function(input) {
  var count = input[input.length - 1] & 0xff;  
  if(count > input.length || count == 0) throw new Error("pad block corrupted");
  
  for(var i = 1; i <= count; i++) {
    if(input[input.length - i] != count) throw new Error("pad block corrupted");
  }
  
  return count;
}