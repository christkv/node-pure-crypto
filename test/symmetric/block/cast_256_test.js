require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  CAST256 = require('symmetric/block/cast_256').CAST256,
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

  "Test CAST-256 Vectors":function(test) {
    var keys = ["2342bb9efa38542c0af75647f29f615d", "2342bb9efa38542cbed0ac83940ac298bac77a7717942863", "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604"];
    var pts = ["00000000000000000000000000000000", "00000000000000000000000000000000", "00000000000000000000000000000000"];
    var cts = ["c842a08972b43d20836c91d1b7530f6b", "1b386c0210dcadcbdd0e41aa08a7a7e8", "4f6a2038286897b9c9870136553317fa"];

    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt data
      var cipher = new CAST256();
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
  //   var key = "0123456712345678234567893456789A";
  //   var pt =  "0123456789ABCDEF0123456789ABCDEF";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  // 
  //   // OFB Mode
  //   var ofb = new OFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //     
  //   var ofb = new OFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CBC Mode
  //   var cbc = new CBCMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var cbc = new CBCMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(src);    
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // ECB Mode
  //   var ecb = new ECBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ecb = new ECBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(src);    
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CFB Mode
  //   var ofb = new CFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "0123456712345678234567893456789A";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   ofb = new OFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   test.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new CAST256(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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

