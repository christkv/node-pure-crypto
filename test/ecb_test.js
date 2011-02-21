require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  AESKey = require('aes').AESKey,
  XTeaKey = require('xtea').XTeaKey,
  ECBMode = require('ecb').ECBMode,
  NullPad = require('padding').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("ECBMode Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "testECB_AES128":function(assert, finished) {
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
    assert.deepEqual(ct, src);

    // Decrypt
    ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    assert.deepEqual(decrypt, pt);
    finished();
  },
  
  "test_ECB_AES192":function(assert, finished) {
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
    assert.deepEqual(ct, src);
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    assert.deepEqual(pt, decrypt);    
    finished();
  },
  
  "test_ECB_AES256":function(assert, finished) {
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
    assert.deepEqual(ct, src);
  
    var ecb = new ECBMode(new AESKey(key), new NullPad());
    var decrypt = ecb.decrypt(src);    
    assert.deepEqual(pt, decrypt);    
    finished();
  },  
  
  // "testAES":function(assert, finished) {
  //    var keys = [
  //    "00010203050607080A0B0C0D0F101112",
  //    "14151617191A1B1C1E1F202123242526"];
  //    var cts = [
  //    "D8F532538289EF7D06B506A4FD5BE9C94894C5508A8D8E29AB600DB0261F0555A8FA287B89E65C0973F1F8283E70C72863FE1C8F1F782084CE05626E961A67B3",
  //    "59AB30F4D4EE6E4FF9907EF65B1FB68C96890CE217689B1BE0C93ED51CF21BB5A0101A8C30714EC4F52DBC9C6F4126067D363F67ABE58463005E679B68F0B496"];
  //    var pts = [
  //    "506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359",
  //    "5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B"];
  //    
  //  for(var i = 0; i < keys.length; i++) {
  //    var key = util.hexStringToBinaryArray(keys[i]);
  //    var pt = util.hexStringToBinaryArray(pts[i]);
  //    var ct = util.hexStringToBinaryArray(cts[i]);
  //    var aes = new AESKey(key);
  //    var iv = util.hexStringToBinaryArray("00000000000000000000000000000000");
  //    var ecb = new ECBMode(aes, null, iv);
  // 
  //    // Encrypt the pt key
  //    var encrypted = ecb.encrypt(pt);
  //    assert.deepEqual(ct, encrypted);
  //    
  //    // Decrypt
  //    var ecb = new ECBMode(aes, null, iv);
  //    var decrypted = ecb.decrypt(encrypted);
  //    assert.deepEqual(pt, decrypted);
  //    finished();
  //  }
  // },
  // 
  // "testXTea":function(assert, finished) {
  //    var keys = [
  //      "2b02056806144976775d0e266c287843",
  //    "00000000000000000000000000000000"];
  //    var cts = [
  //      "790958213819878370eb8251ffdac371081c5a457fc42502c63910306fea150be8674c3b8e675516",
  //    "2dc7e8d3695b0538d8f1640d46dca717790af2ab545e11f3b08e798eb3f17b1744299d4d20b534aa"];
  //    var pts = [
  //      "74657374206d652e74657374206d652e74657374206d652e74657374206d652e",
  //    "0000000000000000000000000000000000000000000000000000000000000000"];
  // 
  //   for(var i = 0; i < keys.length; i++) {
  //     var key = util.hexStringToBinaryArray(keys[i]);
  //     var pt = util.hexStringToBinaryArray(pts[i]);
  //     var ct = util.hexStringToBinaryArray(cts[i]);
  //     var tea = new XTeaKey(key);
  //     var iv = util.hexStringToBinaryArray("00000000000000000000000000000000");
  //     var ecb = new ECBMode(tea, null, iv);
  //     // Encrypt the pt key
  //     var encrypted = ecb.encrypt(pt);
  //     assert.deepEqual(ct, encrypted);
  // 
  //     // Decrypt
  //     var ecb = new ECBMode(tea, null, iv);
  //     var decrypted = ecb.decrypt(encrypted);
  //     assert.deepEqual(pt, decrypted);
  //     finished();
  //   }    
  // },
  // 
  // "Node Compatibility Tests":function(assert, finished) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
  //   var pt = "6bc1bee22e409f96e93d7e117393172a" + 
  //      "ae2d8a571e03ac9c9eb76fac45af8e51" + 
  //      "30c81c46a35ce411e5fbc1191a0a52ef" + 
  //      "f69f2445df4f9b17ad2b417be66c3710";
  //   var ct = "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B3F461796D6B0D6B2E0C2A72B4D80E644";
  // 
  //   // Encrypt using the pure js library    
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.hexStringToBinaryArray(ct), src);
  //   
  //   // Encrypt using the node.js crypto library
  //   var cipher = crypto.createCipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  // 
  //   // Compare the two encrypted contents
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   // Decrypt each others output
  //   var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');
  // 
  //   // Compare the decrypted content
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs)
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   finished();    
  // },
  // 
  // "Streaming api test":function(assert, finished) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + 
  //      "1f352c073b6108d72d9810a30914dff4";         
  //   // 5K of random data
  //   var data = randomdata(1023);    
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / 1024);
  //   var leftOverbytes = data.length % 1024;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //    encryptedData += ecb.updateEncrypt(data.substr(i * 1024, 1024));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) 
  //    encryptedData += ecb.updateEncrypt(data.substr(numberOfBlocks*1024)); 
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += ecb.finalEncrypt();
  // 
  //   // Encrypt using node.js to ensure have have the same
  //   var cipher = crypto.createCipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  // 
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   assert.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("aes-256-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  // 
  //   // Clean ecb instance
  //   ecb = new ECBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(nodejsEncrypted.length / 1024);
  //   var leftOverbytes = nodejsEncrypted.length % 1024;
  //   var decryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ecb.updateDecrypt(nodejsEncrypted.substr(i * 1024, 1024));
  //   }    
  // 
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ecb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*1024));          
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ecb.finalDecrypt();
  // 
  //   // Verify encryption
  //   var a = util.binaryStringToArray(decryptedNode);    
  //   var b = util.binaryStringToArray(decryptedData);    
  //   // Verify the decryption against node.js
  //   assert.deepEqual(b, a);    
  //   finished();
  // },
});

















