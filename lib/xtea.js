//  AESKey
//  Derived from:
//    as3crypto http://code.google.com/p/as3crypto/ by Henri Torgemane
//    A public domain implementation from Karl Malbrain, malbrain@yahoo.com
//    (http://www.geocities.com/malbrain/aestable_c.html)
//  See LICENSE.txt for full license information.
var debug = require('sys').debug,
  inspect = require('sys').inspect,
  puts = require('sys').puts,
  assert = require('assert'),
  chr = String.fromCharCode;  

// Number of encryption runs
var NUM_ROUNDS = 64;

var encodeUInt32 = function(value) {
  var buff = [];
  buff[0] = (value >> 24) & 0xff;			
	buff[1] = (value >> 16) & 0xff;
	buff[2] = (value >> 8) & 0xff;
	buff[3] = value & 0xff;
	return buff;
}

// Decode the int
var decodeUInt32 = function(array, index) {
  return array[index + 3] | array[index + 2] << 8 | array[index + 1] << 16 | array[index + 0] << 24;
}
  
var XTeaKey = exports.XTeaKey = function(key) {
  // Unpack the keys
  var index = 0;
  this.key = [];
  // Decode the key
  this.key.push(decodeUInt32(key, index));
  index = index + 4;
  // this.key.push(BinaryParser.toInt(key.substr(index, 4)));
  this.key.push(decodeUInt32(key, index));
  index = index + 4;
  // this.key.push(BinaryParser.toInt(key.substr(index, 4)));
  this.key.push(decodeUInt32(key, index));
  index = index + 4;
  // this.key.push(BinaryParser.toInt(key.substr(index, 4)));  
  this.key.push(decodeUInt32(key, index));
}

XTeaKey.prototype.getBlockSize = function() { return 8; }

XTeaKey.prototype.encrypt = function(block, index) {
  if(index == null) index = 0;
  // Read the two integers from the block
  var v0 = decodeUInt32(block, index);
  var v1 = decodeUInt32(block, index +  4);
  var delta = 0x9E3779B9;
  var sum = 0;
  
  // Encrypt
	for (var i = 0; i < NUM_ROUNDS; i++) {
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + this.key[sum & 3]);		
		sum += delta;    
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + this.key[(sum>>11) & 3]);
	}

  // Encode the results
  return encodeUInt32(v0).concat(encodeUInt32(v1));
}

XTeaKey.prototype.decrypt = function(block, index) {
  if(index == null) index = 0;
  // Read the two integers from the block
  var v0 = decodeUInt32(block, index);
  var v1 = decodeUInt32(block, index + 4)
  var delta = 0x9E3779B9;
  var sum = delta * NUM_ROUNDS;

  // Decrypt
	for (var i = 0; i < NUM_ROUNDS; i++) {
		v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + this.key[(sum>>11) & 3]);
		sum -= delta;
		v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + this.key[sum & 3]);
	}
  
  // Encode the results
  return encodeUInt32(v0).concat(encodeUInt32(v1));  
}








