require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  AESKey = require('block/aes').AESKey,
  XTeaKey = require('block/xtea').XTeaKey,
  CFBMode = require('block/cfb').CFBMode,
  NullPad = require('padding/null').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("CFBMode Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "testCFB_AES128":function(assert, finished) {
    var key = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = util.hexStringToBinaryArray(
      "6bc1bee22e409f96e93d7e117393172a" + 
  		"ae2d8a571e03ac9c9eb76fac45af8e51" + 
  		"30c81c46a35ce411e5fbc1191a0a52ef" + 
  		"f69f2445df4f9b17ad2b417be66c3710");		
    var ct = util.hexStringToBinaryArray(
			"3b3fd92eb72dad20333449f8e83cfb4a" + 
			"c8a64537a0b3a93fcde3cdad9f1ce58b" + 
			"26751f67a3cbb140b1808cf187a4f4df" + 
			"c04b05357c5d1c0eeac4c66f9ff7f2e6");      
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    
    // Encrypt
    var cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var src = cfb.encrypt(pt);
    assert.deepEqual(ct, src);
    
    // Decrypt
    cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb.decrypt(src);
    assert.deepEqual(decrypt, pt);
    finished();
  },
  
  "test_CBC_AES192":function(assert, finished) {
    var key = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = util.hexStringToBinaryArray(
      "6bc1bee22e409f96e93d7e117393172a" + 
  		"ae2d8a571e03ac9c9eb76fac45af8e51" + 
  		"30c81c46a35ce411e5fbc1191a0a52ef" + 
  		"f69f2445df4f9b17ad2b417be66c3710");		
    var ct = util.hexStringToBinaryArray(
			"cdc80d6fddf18cab34c25909c99a4174" + 
			"67ce7f7f81173621961a2b70171d3d7a" + 
			"2e1e8a1dd59b88b1c8e60fed1efac4c9" + 
			"c05f9f9ca9834fa042ae8fba584b09ff");      
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
  
    // Encrypt
    var cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var src = cfb.encrypt(pt);
    assert.deepEqual(ct, src);
  
    // Decrypt
    cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb.decrypt(src);
    assert.deepEqual(decrypt, pt);
    finished();
  },
  
  "test_CBC_AES256":function(assert, finished) {
    var key = util.hexStringToBinaryArray(
			"603deb1015ca71be2b73aef0857d7781" + 
			"1f352c073b6108d72d9810a30914dff4");      
    var pt = util.hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");      
    var ct = util.hexStringToBinaryArray(
			"dc7e84bfda79164b7ecd8486985d3860" + 
			"39ffed143b28b1c832113c6331e5407b" + 
			"df10132415e54b92a13ed0a8267ae2f9" + 
			"75a385741ab9cef82031623d55b1e471");      
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
  
    // Encrypt
    var cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var src = cfb.encrypt(pt);
    assert.deepEqual(ct, src);
  
    // Decrypt
    cfb = new CFBMode(new AESKey(key), new NullPad(), iv);
    var decrypt = cfb.decrypt(src);
    assert.deepEqual(decrypt, pt);
    finished();
  },  
  
  "Node Compatibility Tests":function(assert, finished) {
    var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
    var pt = "6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710";
    var ct = "DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471";
  
    // Encrypt using the pure js library    
    var iv = "000102030405060708090a0b0c0d0e0f";
    var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = cfb.encrypt(util.hexStringToBinaryArray(pt));
    assert.deepEqual(util.hexStringToBinaryArray(ct), src);
    
    // Encrypt using the node.js crypto library
    var cipher = crypto.createCipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    // Compare the two encrypted contents
    assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    // Decrypt each others output
    var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = cfb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');
      
    // Compare the decrypted content
    assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs)
    assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    finished();    
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "603deb1015ca71be2b73aef0857d7781" + 
       "1f352c073b6108d72d9810a30914dff4";         
    // 5K of random data
    var data = randomdata(33);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var iv = "000102030405060708090a0b0c0d0e0f";
    var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += cfb.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += cfb.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += cfb.finalEncrypt();
      
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
    
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    assert.deepEqual(b, a);
      
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean cbc instance
    cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {  
      decryptedData += cfb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += cfb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += cfb.finalDecrypt();
  
    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    assert.deepEqual(b, a);    
    finished();
  },  
});

















