require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  TreeFish = require('block/treeFish').TreeFish,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils'),
  Long = require('long').Long,
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("TreeFish tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test TreeFish Vectors":function(assert, finished) {
    // long[] three_256_01_key = { 0x1716151413121110L, 0x1F1E1D1C1B1A1918L,
    //         0x2726252423222120L, 0x2F2E2D2C2B2A2928L };
    // long[] three_256_01_input = { 0xF8F9FAFBFCFDFEFFL, 0xF0F1F2F3F4F5F6F7L,
    //         0xE8E9EAEBECEDEEEFL, 0xE0E1E2E3E4E5E6E7L };
    // long[] three_256_01_result = { 0x277610F5036C2E1FL, 0x25FB2ADD1267773EL,
    //         0x9E1D67B3E4B06872L, 0x3F76BC7651B39682L };
    // long[] three_256_01_tweak = { 0x0706050403020100L, 0x0F0E0D0C0B0A0908L };    
    
    // var keys = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"];
    // var pts = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"];
    // var tweaks = ["00000000000000000000000000000000"]
    // var cts = ["94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11"];

    var keys = ["0000000000000000000000000000000000000000000000000000000000000000",
                "17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A2928"];
    var pts = ["0000000000000000000000000000000000000000000000000000000000000000",
               "F8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7"];
    var tweaks = ["00000000000000000000000000000000",
                  "07060504030201000F0E0D0C0B0A0908"]
    var cts = ["94EEEA8B1F2ADA84ADF103313EAE6670952419A1F4B16D53D83F13E63C9F6B11",
               "277610F5036C2E1F25FB2ADD1267773E9E1D67B3E4B068723F76BC7651B39682"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      // var key = util.hexStringToBinaryArray(keys[i]);
      var key = keys[i];
      var pt = util.hexStringToBinaryArray(pts[i]);
      var tweak = util.hexStringToBinaryArray(tweaks[i]);
      // var tweak = tweaks[i];
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var treeFish = new TreeFish(key, tweak);
      var encrypted = treeFish.encrypt(pt);

      // Create inputdata
      var b0 = Long.fromString(pts[i].slice(0, 16), 16);
      var b1 = Long.fromString(pts[i].slice(16, 32), 16);
      var b2 = Long.fromString(pts[i].slice(32, 48), 16);
      var b3 = Long.fromString(pts[i].slice(48, 64), 16);      
      var inputdata = TreeFish.putBytes([b0, b1, b2, b3], [], treeFish.BlockSize);      

      // Create encrypted data
      b0 = Long.fromString(cts[i].slice(0, 16), 16);
      b1 = Long.fromString(cts[i].slice(16, 32), 16);
      b2 = Long.fromString(cts[i].slice(32, 48), 16);
      b3 = Long.fromString(cts[i].slice(48, 64), 16);      
      var ctdata = TreeFish.putBytes([b0, b1, b2, b3], [], treeFish.BlockSize);

      // plaintext feed forward
      for(var i = 0; i < encrypted.length; i++) {
        encrypted[i] = encrypted[i] ^ inputdata[i];
      }
      
      assert.deepEqual(ctdata, encrypted)

      // Decrypt and check
      // plaintext feed backward :-)
      for(var i = 0; i < encrypted.length; i++) {
        encrypted[i] = encrypted[i] ^ inputdata[i];
      }      
      
      // Decrypt data and verify
      treeFish = new TreeFish(key, tweak);
      var decrypted = treeFish.decrypt(encrypted);      
      assert.deepEqual(inputdata, decrypted);
    }
      
    finished();
  },  
  
  // "Streaming api test":function(assert, finished) {
  //   var key = "b1656851699e29fa24b70148503d2dfc";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 16;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   assert.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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
  //   assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
  //   finished();
  // },
});