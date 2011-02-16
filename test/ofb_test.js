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
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    assert.deepEqual(pt, decrypted);
    finished();
  },  

  "OFB AES-192 Test Vectors":function(assert, finished) {
    var key = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = util.hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"cdc80d6fddf18cab34c25909c99a4174" + 
			"fcc28b8d4c63837c09e81700c1100401" + 
			"8d9a9aeac0f6596f559c6d4daf59a5f2" + 
			"6d9f200857ca6c3e9cac524bd9acc92a");

    // Encrypt
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var src = ofb.encrypt(pt);
    assert.deepEqual(ct, src);
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    assert.deepEqual(pt, decrypted);
    finished();
  },  

  "OFB AES-256 Test Vectors":function(assert, finished) {
    var key = util.hexStringToBinaryArray("603deb1015ca71be2b73aef0857d7781" + 
		  "1f352c073b6108d72d9810a30914dff4");		
    var pt = util.hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"dc7e84bfda79164b7ecd8486985d3860" + 
			"4febdc6740d20b3ac88f6ad82a4fb08d" + 
			"71ab47a086e86eedf39d1c5bba97c408" + 
			"0126141d67f37be8538f5a8be740e484");

    // Encrypt
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var src = ofb.encrypt(pt);
    assert.deepEqual(ct, src);
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    assert.deepEqual(pt, decrypted);
    finished();
  },  
});

















