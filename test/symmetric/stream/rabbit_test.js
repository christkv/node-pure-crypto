require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  Rabbit = require('symmetric/stream/rabbit').Rabbit,
  util = require('utils');  
  
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test Rabbit Vectors":function(test) {
    var keys = ["00000000", "DC51C3AC3BFC62F12E3D36FE91281329", "C09B0043E9E9AB0187E0C73383957415",
      "00000000", "00000000", "00000000"];
    var pts = ["00000000000000000000000000000000", "00000000000000000000000000000000",
      "00000000000000000000000000000000", "00000000000000000000000000000000",
      "00000000000000000000000000000000", "00000000000000000000000000000000"];
    var cts = ["02F74A1C26456BF5ECD6A536F05457B1", 
               "9C51E28784C37FE9A127F63EC8F32D3D", 
               "9B60D002FD5CEB32ACCD41A0CD0DB10C",
               "EDB70567375DCD7CD89554F85E27A7C6", 
               "6D7D012292CCDCE0E2120058B94ECD1F", 
               "4D1051A123AFB670BF8D8505C8D85A44"];
    var ivs = [null, null, null, "0000000000000000", "597E26C175F573C3", "2717F4D21A56EBA6"];    
  
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var iv = ivs[i] != null ? util.hexStringToBinaryArray(ivs[i]) : null;
      
      // Encrypt the data and verify
      var rabbit = new Rabbit(key, iv);
      rabbit.init(true, key, iv);
      // Encrypt bytes
      rabbit.processBytes(data, 0, data.length, data, 0);
      // Compare
      test.deepEqual(ct, data);
      
      // Clean data
      data = util.hexStringToBinaryArray(pts[i]);
      // Parse single bytes
      rabbit.init(true, key, iv);
      // Encrypt each byte
      for(var j = 0; j < data.length; j++) {
        data[j] = rabbit.returnByte(data[j]);
      }
      // Compare
      test.deepEqual(ct, data);
      
      // Decrypt data and verify
      rabbit = new Rabbit();
      rabbit.init(false, key, iv);
      // Decrypt bytes
      rabbit.processBytes(data, 0, data.length, data, 0);
      // Compare
      test.deepEqual(util.hexStringToBinaryArray(pts[i]), data);
    }
  
    test.done();
  },
  
  // "Streaming api test":function(test) {
  //   var key = "DC51C3AC3BFC62F12E3D36FE91281329";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var rabbit = new Rabbit(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += rabbit.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += rabbit.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += rabbit.finalEncrypt();    
  //   // One bang encryption
  //   var oneTimeEncryptedData = rabbit.encrypt(util.binaryStringToArray(data));
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
  // 
  //   // Convert onetime encrypted data to binary
  //   oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
  // 
  //   // Clean cbc instance
  //   rabbit = new Rabbit(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
  //   var leftOverbytes = oneTimeEncryptedData.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += rabbit.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += rabbit.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += rabbit.finalDecrypt();
  //     
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
  //   test.done();
  // },    
});

// Test 1: Key setup and encryption/decryption/prng 
// 
// key1 = [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00] 
// 
// out1 = [02 F7 4A 1C 26 45 6B F5 EC D6 A5 36 F0 54 57 B1 
// A7 8A C6 89 47 6C 69 7B 39 0C 9C C5 15 D8 E8 88 
// 96 D6 73 16 88 D1 68 DA 51 D4 0C 70 C3 A1 16 F4] 
// 
// ================================================================================ 
// Test 2: Key setup and encryption/decryption/prng 
// 
// key2 = [C2 1F CF 38 81 CD 5E E8 62 8A CC B0 A9 89 0D F8] 
// 
// out2 = [3D 02 E0 C7 30 55 91 12 B4 73 B7 90 DE E0 18 DF 
// CD 6D 73 0C E5 4E 19 F0 C3 5E C4 79 0E B6 C7 4A 
// B0 BB 1B B7 86 0A 68 5A BF 9C 8F AF 26 3C CA 09] 
// 
// ================================================================================ 
// Test 3: Key setup and encryption/decryption/prng 
// 
// key3 = [1D 27 2C 6A 2D 8E 3D FC AC 14 05 6B 78 D6 33 A0] 
// 
// out3 = [A3 A9 7A BB 80 39 38 20 B7 E5 0C 4A BB 53 82 3D 
// C4 42 37 99 C2 EF C9 FF B3 A4 12 5F 1F 4C 99 A8 
// AE 95 3E 56 D3 8B D2 67 67 C3 64 9E EF 34 D9 19] 
// 
// ================================================================================ 
// Test 4: Key setup, iv setup and encryption/decryption/prng 
// 
// key4 = [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00] 
// 
// iv4 = [00 00 00 00 00 00 00 00] 
// 
// out4 = [ED B7 05 67 37 5D CD 7C D8 95 54 F8 5E 27 A7 C6 
// 8D 4A DC 70 32 29 8F 7B D4 EF F5 04 AC A6 29 5F 
// 66 8F BF 47 8A DB 2B E5 1E 6C DE 29 2B 82 DE 2A] 
// 
// ================================================================================ 
// Test 5: Key setup, iv setup and encryption/decryption/prng 
// 
// key5 = [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00] 
// 
// iv5 = [59 7E 26 C1 75 F5 73 C3] 
// 
// out5 = [6D 7D 01 22 92 CC DC E0 E2 12 00 58 B9 4E CD 1F 
// 2E 6F 93 ED FF 99 24 7B 01 25 21 D1 10 4E 5F A7 
// A7 9B 02 12 D0 BD 56 23 39 38 E7 93 C3 12 C1 EB] 
// 
// ================================================================================ 
// Test 6: Key setup, iv setup and encryption/decryption/prng 
// 
// key6 = [00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00] 
// 
// iv6 = [27 17 F4 D2 1A 56 EB A6] 
// 
// out6 = [4D 10 51 A1 23 AF B6 70 BF 8D 85 05 C8 D8 5A 44 
// 03 5B C3 AC C6 67 AE AE 5B 2C F4 47 79 F2 C8 96 
// CB 51 15 F0 34 F0 3D 31 17 1C A7 5F 89 FC CB 9F] 
// 
// ================================================================================



















