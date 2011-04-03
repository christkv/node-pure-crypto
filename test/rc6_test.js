require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  RC6 = require('block/rc6').RC6,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  NullPad = require('padding/null').NullPad,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("RC6 tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test RC6 Vectors":function(assert, finished) {
    var keys = ["0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe", "0000000000000000000000000000000000000000000000000000000000000000",
      "0123456789abcdef0112233445566778899aabbccddeeff0", "000000000000000000000000000000000000000000000000",
      "0123456789ABCDEF0112233445566778", "00000000000000000000000000000000"];
    var pts = ["02132435465768798a9bacbdcedfe0f1", "00000000000000000000000000000000",
      "02132435465768798a9bacbdcedfe0f1", "00000000000000000000000000000000",
      "02132435465768798A9BACBDCEDFE0F1", "00000000000000000000000000000000"];
    var cts = ["c8241816f0d7e48920ad16a1674e5d48", "8f5fbd0510d15fa893fa3fda6e857ec2",
      "688329d019e505041e52e92af95291d4", "6cd61bcb190b30384e8a3f168690ae82",
      "524E192F4715C6231F51F6367EA43F18", "8FC3A53656B1F778C129DF4E9848A41E"];

    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var rc6 = new RC6(key);
      var encrypted = rc6.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      rc6 = new RC6(key);
      var decrypted = rc6.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  

  "Node Compatibility Tests":function(assert, finished) {
    var key = "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe";
    var pt =  "02132435465768798a9bacbdcedfe0f1";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
      
    // OFB Mode
    var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
      
    var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(src);
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // CBC Mode
    var cbc = new CBCMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
    
    var cbc = new CBCMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = cbc.decrypt(src);    
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // ECB Mode
    var ecb = new ECBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
    
    var ecb = new ECBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ecb.decrypt(src);    
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // CFB Mode
    var ofb = new CFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    
    var ofb = new CFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(src);
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    finished();    
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
    ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    assert.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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