require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  IDEA = require('symmetric/block/idea').IDEA,
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

  "Test IDEA Vectors":function(test) {
    var keys = ["00010002000300040005000600070008", "00010002000300040005000600070008",
      "00010002000300040005000600070008", "00010002000300040005000600070008",
      "00010002000300040005000600070008", "00010002000300040005000600070008",
      "00010002000300040005000600070008", "0005000A000F00140019001E00230028",
      "006400C8012C019001F4025802BC0320", "9D4075C103BC322AFB03E7BE6AB30006",
      "3A984E2000195DB32EE501C8C47CEA60", "00010002000300040005000600070008"]
      
    var pts = ["0000000100020003", "0102030405060708", "0019324B647D96AF",
      "F5202D5B9C671B08", "FAE6D2BEAA96826E", "0A141E28323C4650",
      "050A0F14191E2328", "0102030405060708", "05320A6414C819FA",
      "0808080808080808", "0102030405060708", "0000000100020003"]
      
    var cts = ["11FBED2B01986DE5", "540E5FEA18C2F8B1", "9F0A0AB6E10CED78",
      "CF18FD7355E2C5C5", "85DF52005608193D", "2F7DE750212FB734",
      "7B7314925DE59C09", "3EC04780BEFF6E20", "65BE87E7A2538AED",
      "F5DB1AC45E5EF9F9", "97BCD8200780DA86", "11FBED2B01986DE5"]
          
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt data
      var cipher = new IDEA();
      cipher.init(true, key);
      cipher.processBlock(data, 0);  // Destructive to save memory      
      test.deepEqual(ct, data);
      
      // Initialize cipher for decryption
      cipher.init(false, key);
      // Decrypt the encrypted data and compare
      cipher.processBlock(data, 0);
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }
      
    test.done();
  },  
  
  "Encrypt a long file":function(test) {
    // 5K of random data
    var pt = util.binaryStringToArray(randomdata(32))
    var data = pt.slice(0);
    var key = "00010002000300040005000600070008";
    var encryptedData = [];
    var decryptedData = [];
  
    // Encrypt the data and verify
    var idea = new IDEA(key);    
    idea.init(true, key);
    var numberOfBlocks = data.length / idea.getBlockSize();
    for(var i = 0; i < numberOfBlocks; i++) {
      idea.processBlock(data, (i * idea.getBlockSize()));
    }
    
    // Decrypt
    idea.init(false, key);
    
    for(var i = 0; i < numberOfBlocks; i++) {
      idea.processBlock(data, (i * idea.getBlockSize()));
    }
  
    test.deepEqual(pt, data);
    test.done();
  },
  
  // "Streaming api test":function(test) {
  //   var key = "00010002000300040005000600070008";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   test.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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