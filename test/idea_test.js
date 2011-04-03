require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  IDEA = require('block/idea').IDEA,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("IDEA tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test IDEA Vectors":function(assert, finished) {
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
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var idea = new IDEA(key);
      var encrypted = idea.encrypt(pt);
      assert.deepEqual(ct, encrypted);
  
      // Decrypt data and verify
      idea = new IDEA(key);
      var decrypted = idea.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  
  
  "Encrypt a long file":function(assert, finished) {
    // 5K of random data
    var data = util.binaryStringToArray(randomdata(1024));
    var key = "00010002000300040005000600070008";
    var encryptedData = [];
    var decryptedData = [];

    // Encrypt the data and verify
    var idea = new IDEA(key);    
    var numberOfBlocks = data.length / idea.getBlockSize();
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData = encryptedData.concat(idea.encrypt(data, (i * idea.getBlockSize())));
    }
    
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData = decryptedData.concat(idea.decrypt(encryptedData, (i * idea.getBlockSize())));
    }
    
    assert.deepEqual(data, decryptedData);
    finished();
  },

  "Streaming api test":function(assert, finished) {
    var key = "00010002000300040005000600070008";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += ofb.finalEncrypt();
    
    // Single pass encryption
    ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    assert.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new IDEA(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(src.length / blockSize);
    var leftOverbytes = src.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += ofb.finalDecrypt();

    // Compare
    assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
    finished();
  },
});