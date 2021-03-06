require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  Noekeon = require('symmetric/block/noekeon').Noekeon,
  util = require('utils'),
  crypto = require('crypto');
  
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

  "Test Noekeon Vectors":function(test) {
    var keys = ["00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "b1656851699e29fa24b70148503d2dfc"];
    var pts = ["00000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "2a78421b87c7d0924f26113f1d1349b2"];
    var cts = ["b1656851699e29fa24b70148503d2dfc", "2a78421b87c7d0924f26113f1d1349b2", "e2f687e07b75660ffc372233bc47532c"];
  
    // Test vectors
    // for(var i = 0; i < keys.length; i++) {
      for(var i = 0; i < 1; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);

      // Encrypt data
      var cipher = new Noekeon();
      cipher.init(true, key);
      test.equal(16, cipher.processBlock(data, 0, data, 0));  // Destructive to save memory      
      test.deepEqual(ct, data);

      // Initialize cipher for decryption
      cipher.init(false, key);
      // Decrypt the encrypted data and compare
      test.equal(16, cipher.processBlock(data, 0, data, 0));
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }
      
    test.done();
  },  
  
  // "Streaming api test":function(test) {
  //   var key = "b1656851699e29fa24b70148503d2dfc";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 16;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += ofb.finalEncrypt();
  //   
  //   // Single pass encryption
  //   ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   test.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(src.length / blockSize);
  //   var leftOverbytes = src.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ofb.finalDecrypt();
  // 
  //   // Compare
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
  //   test.done();
  // },  
  // 
  // "Streaming api test":function(test) {
  //   var key = "b1656851699e29fa24b70148503d2dfc";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //   // 5K of random data
  //   // var data = randomdata(33);
  //   var data = util.arrayToBinaryString(zeroedData(33));
  //   // Blocksize
  //   var blockSize = 16;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += ofb.finalEncrypt();
  //   
  //   // Single pass encryption
  //   ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   test.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // var src = encryptedData;
  //   // // Clean cbc instance
  //   // ofb = new OFBMode(new Noekeon(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // // Split the data
  //   // var numberOfBlocks = Math.floor(src.length / blockSize);
  //   // var leftOverbytes = src.length % blockSize;
  //   // var decryptedData = "";
  //   //   
  //   // for(var i = 0; i < numberOfBlocks; i++) {
  //   //   decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(i * blockSize, blockSize));
  //   // }    
  //   // 
  //   // // Update with leftover bytes
  //   // if(leftOverbytes > 0) 
  //   //   decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(numberOfBlocks*blockSize));          
  //   //   
  //   // // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   // decryptedData += ofb.finalDecrypt();
  //   //   
  //   // // Compare
  //   // test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
  //   test.done();
  // },
});