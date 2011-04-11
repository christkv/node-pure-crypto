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
  "Test TreeFish 256 Vectors":function(assert, finished) {
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
      var key = util.hexStringToBinaryArray(keys[i]);
      // var key = keys[i];
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

  "Test TreeFish 512 Vectors":function(assert, finished) {
    var keys = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A292837363534333231303F3E3D3C3B3A393847464544434241404F4E4D4C4B4A4948"];
    var pts = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
               "F8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7D8D9DADBDCDDDEDFD0D1D2D3D4D5D6D7C8C9CACBCCCDCECFC0C1C2C3C4C5C6C7"];
    var tweaks = ["00000000000000000000000000000000",
                  "07060504030201000F0E0D0C0B0A0908"]
    var cts = ["BC2560EFC6BBA2B1E3361F162238EB40FB8631EE0ABBD1757B9479D4C5479ED1CFF0356E58F8C27BB1B7B08430F0E7F7E9A380A56139ABF1BE7B6D4AA11EB47E",
               "D4A32EDD6ABEFA1C6AD5C4252C3FF74335AC875BE2DED68C99A6C774EA5CD06CDCEC9C4251D7F4F8F5761BCB3EF592AFFCABCB6A3212DF60FD6EDE9FF9A2E14E"];
    
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
      var b4 = Long.fromString(pts[i].slice(64 + 0, 64 + 16), 16);
      var b5 = Long.fromString(pts[i].slice(64 + 16, 64 + 32), 16);
      var b6 = Long.fromString(pts[i].slice(64 + 32, 64 + 48), 16);
      var b7 = Long.fromString(pts[i].slice(64 + 48, 64 + 64), 16);      
      var inputdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7], [], treeFish.BlockSize);      
  
      // Create encrypted data
      b0 = Long.fromString(cts[i].slice(0, 16), 16);
      b1 = Long.fromString(cts[i].slice(16, 32), 16);
      b2 = Long.fromString(cts[i].slice(32, 48), 16);
      b3 = Long.fromString(cts[i].slice(48, 64), 16);      
      b4 = Long.fromString(cts[i].slice(64 + 0, 64 + 16), 16);
      b5 = Long.fromString(cts[i].slice(64 + 16, 64 + 32), 16);
      b6 = Long.fromString(cts[i].slice(64 + 32, 64 + 48), 16);
      b7 = Long.fromString(cts[i].slice(64 + 48, 64 + 64), 16);      
      var ctdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7], [], treeFish.BlockSize);
  
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