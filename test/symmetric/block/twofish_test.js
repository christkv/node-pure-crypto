require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  Twofish = require('symmetric/block/twofish').Twofish,
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

  "Test Twofish Vectors":function(test) {
    var keys = ["00000000000000000000000000000000", "00000000000000000000000000000000",
      "9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419",
      "000000000000000000000000000000000000000000000000", "EFA71F788965BD4453F860178FC191010000000000000000",
      "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F"];
    var pts = ["00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A",
      "D491DB16E7B1C39E86CB086B789F5419", "019F9809DE1711858FAAC3A3BA20FBC3",
      "00000000000000000000000000000000", "88B2B2706B105E36B446BB6D731A1E88",
      "39DA69D6BA4997D585B6DC073CA341B2", "00000000000000000000000000000000",
      "90AFE91BB288544F2C32DC239B2635E6"];
    var cts = ["9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419",
      "019F9809DE1711858FAAC3A3BA20FBC3", "6363977DE839486297E661C6C9D668EB",
      "EFA71F788965BD4453F860178FC19101", "39DA69D6BA4997D585B6DC073CA341B2",
      "182B02D81497EA45F9DAACDC29193A65", "57FF739D4DC92C1BD7FC01700CC8216F",
      "6CB4561C40BF0A9705931CB6D408E7FA"];
      
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt data
      var cipher = new Twofish();
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

  // "Node Compatibility Tests":function(test) {
  //   var key = "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100";
  //   var pt =  "02132435465768798a9bacbdcedfe0f1";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //     
  //   // OFB Mode
  //   var ofb = new OFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //     
  //   var ofb = new OFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CBC Mode
  //   var cbc = new CBCMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var cbc = new CBCMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(src);    
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // ECB Mode
  //   var ecb = new ECBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ecb = new ECBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(src);    
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CFB Mode
  //   var ofb = new CFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   ofb = new OFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   test.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new Twofish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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
});