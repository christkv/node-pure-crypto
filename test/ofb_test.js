require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  AESKey = require('aes').AESKey,
  OFBMode = require('ofb').OFBMode,
  NullPad = require('padding').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("OFBMode Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "OFB AES-128 Test Vectors":function(assert, finished) {
    var key = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = util.hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"3b3fd92eb72dad20333449f8e83cfb4a" +
			"7789508d16918f03f53c52dac54ed825" + 
			"9740051e9c5fecf64344f7a82260edcc" + 
			"304c6528f659c77866a510d9c1d6ae5e");

    // Encrypt
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var src = ofb.encrypt(pt);
    assert.deepEqual(ct, src);
    finished();
  },  
});

















