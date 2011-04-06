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

var arrayToBinaryString = exports.arrayToBinaryString = function(array, index, length) {
  var string = "";
  index = index == null ? 0 : index;
  length = length == null ? array.length : length;
  
  for(var i = index; i < length; i++) {
    string += String.fromCharCode(array[i]);
  }  
  return string;  
}

// Decode the int
var inPlaceEncodeUInt32 = exports.inPlaceEncodeUInt32 = function(value, buff, index) {
  buff[index] = (value >> 24) & 0xff;			
	buff[index + 1] = (value >> 16) & 0xff;
	buff[index + 2] = (value >> 8) & 0xff;
	buff[index + 3] = value & 0xff;
}

var encodeUInt32 = exports.encodeUInt32 = function(value) {
  var buff = [];
  buff[0] = (value >> 24) & 0xff;			
	buff[1] = (value >> 16) & 0xff;
	buff[2] = (value >> 8) & 0xff;
	buff[3] = value & 0xff;
	return buff;
}

var encodeUInt16 = exports.encodeUInt16 = function(value) {
  var buff = [];
	buff[0] = (value >> 8) & 0xff;
	buff[1] = value & 0xff;
	return buff;
}

// Decode the int
var inPlaceEncodeUInt16 = exports.inPlaceEncodeUInt16 = function(value, buff, index) {
	buff[index] = (value >> 8) & 0xff;
	buff[index + 1] = value & 0xff;
}

// Decode the int
var decodeUInt32 = exports.decodeUInt32 = function(array, index) {
  return array[index + 3] | array[index + 2] << 8 | array[index + 1] << 16 | array[index + 0] << 24;
}

// Decode the int
var decodeUInt16 = exports.decodeUInt16 = function(array, index) {
  return array[index + 1] | array[index + 0] << 8;
}

// Bit-wise rotate left
var rotl = exports.rotl = function (n, b) {
	return (n << b) | (n >>> (32 - b));
}

// Bit-wise rotate right
var rotr = exports.rotr = function (n, b) {
	return (n << (32 - b)) | (n >>> b);
}

// Swap big-endian to little-endian and vice versa
var endian = exports.endian = function (n) {
	// If number given, swap endian
	if (n.constructor == Number) {
		return rotl(n,  8) & 0x00FF00FF | rotl(n, 24) & 0xFF00FF00;
	}
	// Else, assume array and swap all items
	for (var i = 0; i < n.length; i++)
		n[i] = endian(n[i]);
	return n;
}



