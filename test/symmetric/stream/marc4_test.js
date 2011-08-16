require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  MARC4 = require('symmetric/stream/marc4').MARC4,
  util = require('utils'),
  crypto = require('crypto');
  
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test MARC4 Vectors":function(test) {
    var keys = ["0123456789ABCDEF", "618A63D2FB"];
    var pts = ["0000000000000000", "DCEE4CF92C"];
    var cts = ["7494C2E7104B0879", "F13829C9DE"];
    var drops = [0, 0];    
  
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var drop = drops[i];
      
      // Encrypt data
      var cipher = new MARC4();
      cipher.init(true, key, drop);
      cipher.processBytes(data, 0, data.length, data, 0);  // Destructive to save memory      
      test.deepEqual(ct, data);

      // Encrypt data byte by byte
      var data = util.hexStringToBinaryArray(pts[i]);
      var cipher = new MARC4();
      cipher.init(true, key, drop);
      
      for(var j = 0; j < data.length; j++) {
        data[j] = cipher.returnByte(data[j]);
      }      
      
      test.deepEqual(ct, data);
      
      // Initialize cipher for decryption
      cipher.init(false, key, drop);
      // Decrypt the encrypted data and compare
      cipher.processBytes(data, 0, data.length, data, 0);
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }
      
    test.done();
  },
  
  // "More Arc4 tests - Arc4 is MARC 4 with drop = 0":function(test) {
  //   var key = "Key";
  //   var pt = "Plaintext";
  // 
  //   var marc4 = new MARC4();
  //   marc4.init(true, util.binaryStringToArray(key), 0);
  //   var src = util.binaryStringToArray(pt);
  //   marc4.processBlock(src, 0);
  //   test.deepEqual(util.hexStringToBinaryArray("BBF316E8D940AF0AD3"), src)
  // 
  //   var key = "Wiki";
  //   var pt = "pedia";
  //     
  //   var marc4 = new MARC4();
  //   marc4.init(true, util.binaryStringToArray(key), 0);
  //   var src = util.binaryStringToArray(pt);
  //   marc4.processBlock(src, 0);
  //   test.deepEqual(util.hexStringToBinaryArray("1021BF0420"), src)
  //     
  //   var key = "Secret";
  //   var pt = "Attack at dawn";
  //     
  //   var marc4 = new MARC4();
  //   marc4.init(true, util.binaryStringToArray(key), 0);
  //   var src = util.binaryStringToArray(pt);
  //   marc4.processBlock(src, 0);
  //   test.deepEqual(util.hexStringToBinaryArray("45A01F645FC35B383552544B9BF5"), src)  
  //   test.done();
  // },
  
  // "Streaming api test":function(test) {
  //   var key = "DC51C3AC3BFC62F12E3D36FE91281329";
  //   // var key = [0xDC, 0x51, 0xC3, 0xAC, 0x3B, 0xFC, 0x62, 0xF1, 0x2E, 0x3D, 0x36, 0xFE, 0x91, 0x28, 0x13, 0x29];    
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(5000);
  //   // Blocksize
  //   var blockSize = 1536;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var marc4 = new MARC4(util.hexStringToBinaryArray(key));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += marc4.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  //     
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += marc4.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += marc4.finalEncrypt();    
  //   
  //   // Reinitialize the marc encryptor
  //   marc4 = new MARC4(util.hexStringToBinaryArray(key));
  //   // One bang encryption
  //   var oneTimeEncryptedData = marc4.encrypt(util.binaryStringToArray(data));
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
  //     
  //   // Convert onetime encrypted data to binary
  //   oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
  //     
  //   // Clean cbc instance
  //   marc4 = new MARC4(util.hexStringToBinaryArray(key));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
  //   var leftOverbytes = oneTimeEncryptedData.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += marc4.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += marc4.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += marc4.finalDecrypt();
  //     
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
  //   test.done();
  // },    
});