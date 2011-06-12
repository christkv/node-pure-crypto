require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  AESKey = require('symmetric/block/aes').AESKey,
  XTeaKey = require('symmetric/block/xtea').XTeaKey,
  CFB8Mode = require('symmetric/block/cfb8').CFB8Mode,
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

  "testCFB8_AES128":function(test) {
    var key = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172aae2d");
    var ct = util.hexStringToBinaryArray("3b79424c9c0dd436bace9e0ed4586a4f32b9");
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    
    // Encrypt
    var cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var src = cfb8.encrypt(pt);
    test.deepEqual(ct, src);
    
    // Decrypt
    cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb8.decrypt(src);
    test.deepEqual(decrypt, pt);
    test.done();
  },
  
  "test_CBC_AES192":function(test) {
    var key = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172aae2d");
    var ct = util.hexStringToBinaryArray("cda2521ef0a905ca44cd057cbf0d47a0678a");
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
  
    // Encrypt
    var cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var src = cfb8.encrypt(pt);
    test.deepEqual(ct, src);

    // Decrypt
    cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb8.decrypt(src);
    test.deepEqual(decrypt, pt);
    test.done();
  },
  
  "test_CBC_AES256":function(test) {
    var key = util.hexStringToBinaryArray("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");      
    var pt = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172aae2d");
    var ct = util.hexStringToBinaryArray("dc1f1a8520a64db55fcc8ac554844e889700");
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
  
    // Encrypt
    var cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var src = cfb8.encrypt(pt);
    test.deepEqual(ct, src);

    // Decrypt
    cfb8 = new CFB8Mode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb8.decrypt(src);
    test.deepEqual(decrypt, pt);
    test.done();
  },  
  
  "Node Compatibility Tests":function(test) {
    var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
    var pt = "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710";
    var ct = "DC1F1A8520A64DB55FCC8AC554844E889700ADC6E10C63CF2D8CD2D8CE668F3EB9191719C47444FB43BFF9B9883C2CD051120402009F974998C89D195722A75B";
  
    // Encrypt using the pure js library    
    var iv = "000102030405060708090a0b0c0d0e0f";
    var cfb8 = new CFB8Mode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = cfb8.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.hexStringToBinaryArray(ct), src);
    
    // Encrypt using the node.js crypto library
    var cipher = crypto.createCipheriv("aes-256-cfb8", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("aes-256-cfb8", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
  
    // Compare the two encrypted contents
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    // Decrypt each others output
    var cfb8 = new CFB8Mode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = cfb8.decrypt(util.binaryStringToArray(nodeEncrypted));
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
    var cfb8 = new CFB8Mode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += cfb8.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += cfb8.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += cfb8.finalEncrypt();
      
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("aes-256-cfb8", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
    
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    test.deepEqual(b, a);
      
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("aes-256-cfb8", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean cbc instance
    cfb8 = new CFB8Mode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {  
      decryptedData += cfb8.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += cfb8.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += cfb8.finalDecrypt();

    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    test.deepEqual(b, a);    
    test.done();
  },  
});

















