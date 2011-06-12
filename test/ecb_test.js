require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  AESKey = require('symmetric/block/aes').AESKey,
  XTeaKey = require('symmetric/block/xtea').XTeaKey,
  ECBMode = require('symmetric/block/ecb').ECBMode,
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

  "testECB_AES128":function(test) {
    var key = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"3ad77bb40d7a3660a89ecaf32466ef97" + 
			"f5d3d58503b9699de785895a96fdbaaf" + 
			"43b1cd7f598ece23881b00e3ed030688" + 
			"7b0c785e27e8ad3f8223207104725dd4");

    // Encrypt
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var src = ecb.encrypt(pt);
    test.deepEqual(ct, src);

    // Decrypt
    ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    test.deepEqual(decrypt, pt);
    test.done();
  },
  
  "test_ECB_AES192":function(test) {
    var key = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"bd334f1d6e45f25ff712a214571fa5cc" + 
			"974104846d0ad3ad7734ecb3ecee4eef" + 
			"ef7afd2270e2e60adce0ba2face6444e" + 
			"9a4b41ba738d6c72fb16691603c18e0e");
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var src = ecb.encrypt(pt);
    test.deepEqual(ct, src);
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    test.deepEqual(pt, decrypt);    
    test.done();
  },
  
  "test_ECB_AES256":function(test) {
    var key = util.hexStringToBinaryArray(
      "603deb1015ca71be2b73aef0857d7781" + 
       "1f352c073b6108d72d9810a30914dff4");      
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
			"f3eed1bdb5d2a03c064b5a7e3db181f8" + 
			"591ccb10d410ed26dc5ba74a31362870" + 
			"b6ed21b99ca6f4f9f153e7b1beafed1d" + 
			"23304b7a39f9f3ff067d8d8f9e24ecc7");
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var src = ecb.encrypt(pt);
    test.deepEqual(ct, src);
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    test.deepEqual(pt, decrypt);    
    test.done();
  },  

  "Node Compatibility Tests":function(test) {
    var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
    var pt = "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710";
    var ct = "F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC74C45DFB3B3B484EC35B0512DC8C1C4D6";
  
    // Encrypt using the pure js library    
    var iv = "00000000000000000000000000000000";
    var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.hexStringToBinaryArray(ct), src);
    
    // Encrypt using the node.js crypto library
    var cipher = crypto.createCipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
  
    // Compare the two encrypted contents
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    // Decrypt each others output
    var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
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
    var data = randomdata(1023);
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var iv = "000102030405060708090a0b0c0d0e0f";
    var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    // Blocksize
    var blockSize = 32;
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
     encryptedData += ecb.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) 
     encryptedData += ecb.updateEncrypt(data.substr(numberOfBlocks*blockSize)); 
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += ecb.finalEncrypt();
  
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
  
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    test.deepEqual(b, a);
  
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean ecb instance
    ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));

    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += ecb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
      
    // Update with leftover bytes
    if(leftOverbytes > 0) {
      decryptedData += ecb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));
    }
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += ecb.finalDecrypt();
      
    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    test.deepEqual(b, a);    
    test.done();
  },
});

















