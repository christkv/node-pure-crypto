require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  SkipJack = require('block/skipjack').SkipJack,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("SkipJack tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test SkipJack Vectors":function(assert, finished) {
    var keys = ["00998877665544332211", "e7496e99e4628b7f9ffb", "e7496e99e4628b7f9ffb", "e5caf4dcc70e55f1dd90", "e5caf4dcc70e55f1dd90",
      "cde4bef260d7bcda1635", "7022907dd1dff7dac5c9", "568f86edd1dc9268eeee", "689daaa9060d2d4b6003", "6c160f11896c4794846e"];
    var pts = ["33221100ddccbbaa", "99ccfe2b90fd550b", "60a73d387b517fca", "b71cb0d009af2765", "64f4877ae68a8a62",
      "47d348b7551195e7", "941d26d0c6eb14ad", "533285a6ed810c9b", "062365b0a54364c7", "cfa14a7130c9f137"];
    var cts = ["2587cae27a12d300", "60a73d387b517fca", "24c90cb05d668b27", "64f4877ae68a8a62", "fee778a838a601cd",
      "f17b3070144aebea", "a055d02c5e0eae8d", "b4c22f4fb74c35dc", "08698d8786f80d16", "d6db848b7cecdd39"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var skipjack = new SkipJack(key);
      var encrypted = skipjack.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      skipjack = new SkipJack(key);
      var decrypted = skipjack.decrypt(encrypted);
      assert.deepEqual(util.hexStringToBinaryArray(pts[i]), decrypted);
    }
      
    finished();
  },  
  
  "Streaming api test":function(assert, finished) {
    var key = "00998877665544332211";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 8;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new SkipJack(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
    ofb = new OFBMode(new SkipJack(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    assert.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new SkipJack(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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