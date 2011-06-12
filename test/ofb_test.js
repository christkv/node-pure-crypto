require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  AESKey = require('symmetric/block/aes').AESKey,
  OFBMode = require('symmetric/block/ofb').OFBMode,
  NullPad = require('symmetric/padding/null').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "OFB AES-128 Test Vectors":function(test) {
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
    test.deepEqual(ct, src);
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    test.deepEqual(pt, decrypted);
    test.done();
  },  
  
  "OFB AES-192 Test Vectors":function(test) {
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
    test.deepEqual(ct, src);
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    test.deepEqual(pt, decrypted);
    test.done();
  },  
  
  "OFB AES-256 Test Vectors":function(test) {
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
    test.deepEqual(ct, src);
    
    // Decrypt
    var ofb = new OFBMode(new AESKey(key), new NullPad(), iv);
    var decrypted = ofb.decrypt(src);
    test.deepEqual(pt, decrypted);
    test.done();
  },  
  
  "Node Compatibility Tests":function(test) {
    var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
    var pt = "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710";
    var ct = "DC7E84BFDA79164B7ECD8486985D38604FEBDC6740D20B3AC88F6AD82A4FB08D71AB47A086E86EEDF39D1C5BBA97C4080126141D67F37BE8538F5A8BE740E484";
  
    // Encrypt using the pure js library    
    var iv = "000102030405060708090a0b0c0d0e0f";
    var ofb = new OFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.hexStringToBinaryArray(ct), src);
    
    // Encrypt using the node.js crypto library
    var cipher = crypto.createCipheriv("aes-256-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("aes-256-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
  
    // Compare the two encrypted contents
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    // Decrypt each others output
    var ofb = new OFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');
      
    // Compare the decrypted content
    test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs)
    test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.done();    
  },
  
  "Streaming api test":function(test) {
    var key = "603deb1015ca71be2b73aef0857d7781" + 
       "1f352c073b6108d72d9810a30914dff4";         
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var iv = "000102030405060708090a0b0c0d0e0f";
    var ofb = new OFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += ofb.finalEncrypt();
  
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("aes-256-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
    
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    test.deepEqual(b, a);
  
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("aes-256-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean cbc instance
    ofb = new OFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          

    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += ofb.finalDecrypt();
      
    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    test.deepEqual(b, a);    
    test.done();
  },  
});

















