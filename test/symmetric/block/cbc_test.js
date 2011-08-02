require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  AES = require('symmetric/block/aes').AES,
  XTea = require('symmetric/block/xtea').XTea,
  CBC = require('symmetric/block/cbc').CBC,
  NullPad = require('symmetric/padding/null').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "testCBC_AES128":function(test) {
    var key = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
      "7649abac8119b246cee98e9b12e9197d" + 
      "5086cb9b507219ee95db113a917678b2" + 
      "73bed6b8e3c1743b7116e69e22229516" + 
      "3ff1caa1681fac09120eca307586e1a7");
  
    // Encrypt
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(true, iv, key);
    
    var encrypted = pt.slice(0);
    
    for(var i = 0; i < pt.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }
    
    test.deepEqual(ct, encrypted);
    
    // Decrypt data
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(false, iv, key);

    for(var i = 0; i < encrypted.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }

    test.deepEqual(pt, encrypted);      
    test.done();
  },
  
  "test_CBC_AES192":function(test) {
    var key = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
       "4f021db243bc633d7178183a9fa071e8" + 
       "b4d9ada9ad7dedf4e5e738763f69145a" + 
       "571b242012fb7ae07fa9baac3df102e0" + 
       "08b0e27988598881d920a9e64f5615cd");
  
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(true, iv, key);
    
    var encrypted = pt.slice(0);
    
    for(var i = 0; i < pt.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }
    
    test.deepEqual(ct, encrypted);

    // Decrypt data
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(false, iv, key);

    for(var i = 0; i < encrypted.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }

    test.deepEqual(pt, encrypted);      
    test.done();
  },
  
  "test_CBC_AES256":function(test) {
    var key = util.hexStringToBinaryArray(
      "603deb1015ca71be2b73aef0857d7781" + 
       "1f352c073b6108d72d9810a30914dff4");      
    var pt = util.hexStringToBinaryArray(
       "6bc1bee22e409f96e93d7e117393172a" + 
       "ae2d8a571e03ac9c9eb76fac45af8e51" + 
       "30c81c46a35ce411e5fbc1191a0a52ef" + 
       "f69f2445df4f9b17ad2b417be66c3710");
    var ct = util.hexStringToBinaryArray(
       "f58c4c04d6e5f1ba779eabfb5f7bfbd6" + 
       "9cfc4e967edb808d679f777bc6702c7d" + 
       "39f23369a9d9bacfa530e26304231461" + 
       "b2eb05e2c39be9fcda6c19078c6a9d1b");
  
    var iv = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(true, iv, key);
    
    var encrypted = pt.slice(0);
    
    for(var i = 0; i < pt.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }
    
    test.deepEqual(ct, encrypted);

    // Decrypt data
    var aes = new AES();
    var cbc = new CBC(aes)
    cbc.init(false, iv, key);

    for(var i = 0; i < encrypted.length; i+=16) {
      cbc.processBlock(encrypted, i);
    }

    test.deepEqual(pt, encrypted);      
    test.done();
  },  
  
  "testAES":function(test) {
    var keys = [
    "00010203050607080A0B0C0D0F101112",
    "14151617191A1B1C1E1F202123242526"];
    var cts = [
    "D8F532538289EF7D06B506A4FD5BE9C94894C5508A8D8E29AB600DB0261F0555A8FA287B89E65C0973F1F8283E70C72863FE1C8F1F782084CE05626E961A67B3",
    "59AB30F4D4EE6E4FF9907EF65B1FB68C96890CE217689B1BE0C93ED51CF21BB5A0101A8C30714EC4F52DBC9C6F4126067D363F67ABE58463005E679B68F0B496"];
    var pts = [
    "506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359",
    "5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B"];
     
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var aes = new AES();
      var iv = util.hexStringToBinaryArray("00000000000000000000000000000000");
      var cbc = new CBC(aes);
      cbc.init(true, iv, key)

      // Encrypt the pt key
      var encrypted = pt.slice(0);

      for(var j = 0; j < encrypted.length; j+=16) {
       cbc.processBlock(encrypted, j);       
      }      
      test.deepEqual(ct.slice(0, encrypted.length), encrypted)

      // Decrypt
      var cbc = new CBC(aes);
      cbc.init(false, iv, key)

      for(var j = 0; j < encrypted.length; j+=16) {
       cbc.processBlock(encrypted, j);       
      }
      test.deepEqual(pt, encrypted);
    }

    test.done();
  },
  
  "testXTea":function(test) {
    var keys = [
     "2b02056806144976775d0e266c287843",
    "00000000000000000000000000000000"];
    var cts = [
     "790958213819878370eb8251ffdac371081c5a457fc42502c63910306fea150be8674c3b8e675516",
    "2dc7e8d3695b0538d8f1640d46dca717790af2ab545e11f3b08e798eb3f17b1744299d4d20b534aa"];
    var pts = [
     "74657374206d652e74657374206d652e74657374206d652e74657374206d652e",
    "0000000000000000000000000000000000000000000000000000000000000000"];
  
    var keys = [
     "2b02056806144976775d0e266c287843"];
    var cts = [
     "d2700f838d9f1da5e1aef904d9a523c8a5f86af44275d381f9e6cceb70b0dcfc"];
    var pts = [
     "74657374206d652e74657374206d652e74657374206d652e74657374206d652e"];
  
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var tea = new XTea();
      var iv = util.hexStringToBinaryArray("0000000000000000");
      var cbc = new CBC(tea);
      cbc.init(true, iv, key)

      // Encrypt the pt key
      var encrypted = pt.slice(0);

      for(var j = 0; j < encrypted.length; j+=8) {
       cbc.processBlock(encrypted, j);       
      }      

      // Decrypt
      var cbc = new CBC(tea);
      cbc.init(false, iv, key)

      for(var j = 0; j < encrypted.length; j+=8) {
       cbc.processBlock(encrypted, j);       
      }
      test.deepEqual(pt, encrypted);
      test.done();
    }    
  },
  
  // "Node Compatibility Tests":function(test) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
  //   var pt = "6bc1bee22e409f96e93d7e117393172a" + 
  //      "ae2d8a571e03ac9c9eb76fac45af8e51" + 
  //      "30c81c46a35ce411e5fbc1191a0a52ef" + 
  //      "f69f2445df4f9b17ad2b417be66c3710";
  //   var ct = "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B3F461796D6B0D6B2E0C2A72B4D80E644";
  // 
  //   // Encrypt using the pure js library    
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var cbc = new CBC(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.hexStringToBinaryArray(ct), src);
  //   
  //   // Encrypt using the node.js crypto library
  //   var cipher = crypto.createCipheriv("aes-256-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("aes-256-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //     
  //   // Compare the two encrypted contents
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   // Decrypt each others output
  //   var cbc = new CBC(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');
  //     
  //   // Compare the decrypted content
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs)
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + 
  //      "1f352c073b6108d72d9810a30914dff4";         
  //   // 5K of random data
  //   var data = randomdata(1025);    
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var cbc = new CBC(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   // Blocksize
  //   var blockSize = 16;
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //    encryptedData += cbc.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) 
  //    encryptedData += cbc.updateEncrypt(data.substr(numberOfBlocks*blockSize)); 
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += cbc.finalEncrypt();
  // 
  //   // Encrypt using node.js to ensure have have the same
  //   var cipher = crypto.createCipheriv("aes-256-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  // 
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   test.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("aes-256-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   cbc = new CBC(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
  //   var leftOverbytes = nodejsEncrypted.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += cbc.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
  //   }
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) {
  //     decryptedData += cbc.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));                
  //   }
  // 
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += cbc.finalDecrypt();
  //     
  //   // Verify encryption
  //   var a = util.binaryStringToArray(decryptedNode);    
  //   var b = util.binaryStringToArray(decryptedData);    
  //   // Verify the decryption against node.js
  //   test.deepEqual(b, a);    
  //   test.done();
  // },
});


















