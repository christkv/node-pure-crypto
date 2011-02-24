var copy = exports.copy = function(targetArray, destIndex, sourceArray, sourceIndex, sourceLength) {
  var index = sourceIndex;

  for(var i = destIndex; i < destIndex + sourceLength; i++) {
    targetArray[i] = sourceArray[index++];
  }
}

var hexStringToBinaryArray = exports.hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }  
  return array;
}

var hexStringToBinary = exports.hexStringToBinary = function(string) {
  var numberofValues = string.length / 2;
  var array = "";
  
  for(var i = 0; i < numberofValues; i++) {
    array += String.fromCharCode(parseInt(string[i*2] + string[i*2 + 1], 16));
  }  
  return array;
}

var toHex = exports.toHex = function(array) {
  var s = "";
  for(var i = 0; i < array.length; i++) {
    var v = array[i].toString(16);
    if(v.length == 1) v = "0" + v; 
    s += v.toUpperCase();
  }
  return s;
}

var binaryStringToArray = exports.binaryStringToArray = function(string) {
  var array = [];
  
  for (var i = 0; i < string.length; i++) {
    if (string.charCodeAt(i)<32) {array.push(string.charCodeAt(i));}
    else {array.push(string.charCodeAt(i))}    
  }  
  return array;
}

var arrayToBinaryString = exports.arrayToBinaryString = function(array) {
  var string = "";
  
  for(var i = 0; i < array.length; i++) {
    string += String.fromCharCode(array[i]);
  }  
  return string;  
}

var encodeUInt32 = exports.encodeUInt32 = function(value) {
  var buff = [];
  buff[0] = (value >> 24) & 0xff;			
	buff[1] = (value >> 16) & 0xff;
	buff[2] = (value >> 8) & 0xff;
	buff[3] = value & 0xff;
	return buff;
}

// Decode the int
var decodeUInt32 = exports.decodeUInt32 = function(array, index) {
  return array[index + 3] | array[index + 2] << 8 | array[index + 1] << 16 | array[index + 0] << 24;
}