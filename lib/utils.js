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
