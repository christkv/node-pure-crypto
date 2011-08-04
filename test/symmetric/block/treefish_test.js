require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  TreeFish = require('symmetric/block/treeFish').TreeFish,
  NullPad = require('symmetric/padding/null').NullPad,
  util = require('utils'),
  Long = require('long').Long,
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

  "Test TreeFish 256 Vectors":function(test) {
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
      var data = util.hexStringToBinaryArray(pts[i]);
      var tweak = util.hexStringToBinaryArray(tweaks[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var treeFish = new TreeFish();
      treeFish.init(true, key, tweak);
      // Encrypt data
      test.equal(32, treeFish.processBlock(data, 0, data, 0));
      
      // Create inputdata
      var b0 = Long.fromString(pts[i].slice(0, 16), 16);
      var b1 = Long.fromString(pts[i].slice(16, 32), 16);
      var b2 = Long.fromString(pts[i].slice(32, 48), 16);
      var b3 = Long.fromString(pts[i].slice(48, 64), 16);      
      var inputdata = TreeFish.putBytes([b0, b1, b2, b3], [], 0, treeFish.getBlockSize());      
  
      // Create encrypted data
      b0 = Long.fromString(cts[i].slice(0, 16), 16);
      b1 = Long.fromString(cts[i].slice(16, 32), 16);
      b2 = Long.fromString(cts[i].slice(32, 48), 16);
      b3 = Long.fromString(cts[i].slice(48, 64), 16);      
      var ctdata = TreeFish.putBytes([b0, b1, b2, b3], [], 0, treeFish.getBlockSize());
        
      // plaintext feed forward
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }
      
      test.deepEqual(ctdata, data);
        
      // Decrypt and check
      // plaintext feed backward :-)
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }      
      
      // Decrypt data and verify
      treeFish = new TreeFish();
      treeFish.init(false, key, tweak);      
      test.equal(32, treeFish.processBlock(data, 0, data, 0));     
      // Equal 
      test.deepEqual(inputdata, data);
    }
      
    test.done();
  },  
  
  "Test TreeFish 512 Vectors":function(test) {
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
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var tweak = util.hexStringToBinaryArray(tweaks[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var treeFish = new TreeFish();
      treeFish.init(true, key, tweak);
      test.equal(64, treeFish.processBlock(data, 0, data, 0));
  
      // Create inputdata
      var b0 = Long.fromString(pts[i].slice(0, 16), 16);
      var b1 = Long.fromString(pts[i].slice(16, 32), 16);
      var b2 = Long.fromString(pts[i].slice(32, 48), 16);
      var b3 = Long.fromString(pts[i].slice(48, 64), 16);      
      var b4 = Long.fromString(pts[i].slice(64 + 0, 64 + 16), 16);
      var b5 = Long.fromString(pts[i].slice(64 + 16, 64 + 32), 16);
      var b6 = Long.fromString(pts[i].slice(64 + 32, 64 + 48), 16);
      var b7 = Long.fromString(pts[i].slice(64 + 48, 64 + 64), 16);      
      var inputdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7], [], 0, treeFish.BlockSize);      
  
      // Create encrypted data
      b0 = Long.fromString(cts[i].slice(0, 16), 16);
      b1 = Long.fromString(cts[i].slice(16, 32), 16);
      b2 = Long.fromString(cts[i].slice(32, 48), 16);
      b3 = Long.fromString(cts[i].slice(48, 64), 16);      
      b4 = Long.fromString(cts[i].slice(64 + 0, 64 + 16), 16);
      b5 = Long.fromString(cts[i].slice(64 + 16, 64 + 32), 16);
      b6 = Long.fromString(cts[i].slice(64 + 32, 64 + 48), 16);
      b7 = Long.fromString(cts[i].slice(64 + 48, 64 + 64), 16);      
      var ctdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7], [], 0, treeFish.BlockSize);
  
      // plaintext feed forward
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }
      
      test.deepEqual(ctdata, data)
  
      // Decrypt and check
      // plaintext feed backward :-)
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }      
      
      // Decrypt data and verify
      treeFish = new TreeFish();
      treeFish.init(false, key, tweak);
      test.equal(64, treeFish.processBlock(data, 0, data, 0));
      test.deepEqual(inputdata, data);
    }
      
    test.done();
  },  
  
  "Test TreeFish 1024 Vectors":function(test) {
    var keys = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" 
              + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A292837363534333231303F3E3D3C3B3A393847464544434241404F4E4D4C4B4A4948"
              + "57565554535251505F5E5D5C5B5A595867666564636261606F6E6D6C6B6A696877767574737271707F7E7D7C7B7A797887868584838281808F8E8D8C8B8A8988"];
  
    var pts = ["00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" 
             + "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
               "F8F9FAFBFCFDFEFFF0F1F2F3F4F5F6F7E8E9EAEBECEDEEEFE0E1E2E3E4E5E6E7D8D9DADBDCDDDEDFD0D1D2D3D4D5D6D7C8C9CACBCCCDCECFC0C1C2C3C4C5C6C7"
             + "B8B9BABBBCBDBEBFB0B1B2B3B4B5B6B7A8A9AAABACADAEAFA0A1A2A3A4A5A6A798999A9B9C9D9E9F909192939495969788898A8B8C8D8E8F8081828384858687"];
                      
    var tweaks = ["00000000000000000000000000000000",
                  "07060504030201000F0E0D0C0B0A0908"]
    var cts = ["04B3053D0A3D5CF00136E0D1C7DD85F7067B212F6EA78A5C0DA9C10B4C54E1C60F4EC27394CBACF032437F0568EA4FD5CFF56D1D7654B49CA2D5FB14369B2E7B"
             + "540306B460472E0B71C18254BCEA820DC36B4068BEAF32C8FA4329597A360095C4A36C28434A5B9AD54331444B1046CFDF11834830B2A4601E39E8DFE1F7EE4F",
               "483AC62C27B09B594CB85AA9E48221AA80BC1644069F7D0BFCB26748FF92B235E83D70243B5D294B316A3CA3587A0E025461FD7C8EF6C1B97DD5C1A4C98CA574"
             + "FDA694875AA31A3503D1319C26C2624CA2066D0DF2BF78276831CCDAA5C8A3702B8FCD9189698DACE47818BBFD604399DF47E519CBCEA5415EFD5FF4A5D4C259"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var tweak = util.hexStringToBinaryArray(tweaks[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var treeFish = new TreeFish();
      treeFish.init(true, key, tweak);
      test.equal(128, treeFish.processBlock(data, 0, data, 0));
  
      // Create inputdata
      var b0 = Long.fromString(pts[i].slice(0, 16), 16);
      var b1 = Long.fromString(pts[i].slice(16, 32), 16);
      var b2 = Long.fromString(pts[i].slice(32, 48), 16);
      var b3 = Long.fromString(pts[i].slice(48, 64), 16);      
      var b4 = Long.fromString(pts[i].slice(64 + 0, 64 + 16), 16);
      var b5 = Long.fromString(pts[i].slice(64 + 16, 64 + 32), 16);
      var b6 = Long.fromString(pts[i].slice(64 + 32, 64 + 48), 16);
      var b7 = Long.fromString(pts[i].slice(64 + 48, 64 + 64), 16);      
      var b8 = Long.fromString(pts[i].slice(128 + 0, 128 + 16), 16);
      var b9 = Long.fromString(pts[i].slice(128 + 16, 128 + 32), 16);
      var b10 = Long.fromString(pts[i].slice(128 + 32, 128 + 48), 16);
      var b11 = Long.fromString(pts[i].slice(128 + 48, 128 + 64), 16);      
      var b12 = Long.fromString(pts[i].slice(192 + 0, 192 + 16), 16);
      var b13 = Long.fromString(pts[i].slice(192 + 16, 192 + 32), 16);
      var b14 = Long.fromString(pts[i].slice(192 + 32, 192 + 48), 16);
      var b15 = Long.fromString(pts[i].slice(192 + 48, 192 + 64), 16);      
      var inputdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15], [], 0, treeFish.BlockSize);      
  
      // Create encrypted data
      b0 = Long.fromString(cts[i].slice(0, 16), 16);
      b1 = Long.fromString(cts[i].slice(16, 32), 16);
      b2 = Long.fromString(cts[i].slice(32, 48), 16);
      b3 = Long.fromString(cts[i].slice(48, 64), 16);      
      b4 = Long.fromString(cts[i].slice(64 + 0, 64 + 16), 16);
      b5 = Long.fromString(cts[i].slice(64 + 16, 64 + 32), 16);
      b6 = Long.fromString(cts[i].slice(64 + 32, 64 + 48), 16);
      b7 = Long.fromString(cts[i].slice(64 + 48, 64 + 64), 16);      
      b8 = Long.fromString(cts[i].slice(128 + 0, 128 + 16), 16);
      b9 = Long.fromString(cts[i].slice(128 + 16, 128 + 32), 16);
      b10 = Long.fromString(cts[i].slice(128 + 32, 128 + 48), 16);
      b11 = Long.fromString(cts[i].slice(128 + 48, 128 + 64), 16);      
      b12 = Long.fromString(cts[i].slice(192 + 0, 192 + 16), 16);
      b13 = Long.fromString(cts[i].slice(192 + 16, 192 + 32), 16);
      b14 = Long.fromString(cts[i].slice(192 + 32, 192 + 48), 16);
      b15 = Long.fromString(cts[i].slice(192 + 48, 192 + 64), 16);      
      var ctdata = TreeFish.putBytes([b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15], [], 0, treeFish.BlockSize);
  
      // plaintext feed forward
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }
      
      test.deepEqual(ctdata, data)
  
      // Decrypt and check
      // plaintext feed backward :-)
      for(var i = 0; i < data.length; i++) {
        data[i] = data[i] ^ inputdata[i];
      }      
      
      // Decrypt data and verify
      treeFish = new TreeFish();
      treeFish.init(false, key, tweak);
      test.equal(128, treeFish.processBlock(data, 0, data, 0));
      test.deepEqual(inputdata, data);
    }
      
    test.done();
  },  
  
  // "Streaming api test":function(test) {
  //   var key = "17161514131211101F1E1D1C1B1A191827262524232221202F2E2D2C2B2A2928";
  //   var tweak = "07060504030201000F0E0D0C0B0A0908";
  //   // Encrypt using the pure js library    
  //   var iv = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
  //   // 5K of random data
  //   var data = zeroedData(1024);
  //   // Blocksize
  //   var blockSize = 32;
  // 
  //   var treeFish = new TreeFish(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(tweak));
  //   var encrypted = [];
  //   var numberOfBlocks = data.length/blockSize;
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encrypted = encrypted.concat(treeFish.encrypt(data.slice(i*blockSize, i*blockSize + blockSize)));
  //   }
  //   
  //   var decrypted = [];
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decrypted = decrypted.concat(treeFish.decrypt(encrypted.slice(i*blockSize, i*blockSize + blockSize)));
  //   }
  //   
  //   // Check that we have a valid decrypted data array
  //   test.deepEqual(data, decrypted);
  //   var data = zeroedData(1025);
  // 
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(tweak)), null, util.hexStringToBinaryArray(iv));
  //   encrypted = ofb.encrypt(data);
  // 
  //   var ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(tweak)), null, util.hexStringToBinaryArray(iv));
  //   decrypted = ofb.decrypt(encrypted);
  //   test.deepEqual(data, decrypted)
  // 
  //   var ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(tweak)), null, util.hexStringToBinaryArray(iv));
  //   var data = util.arrayToBinaryString(zeroedData(1025));
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
  //   // Clean cbc instance
  //   ofb = new OFBMode(new TreeFish(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(tweak)), null, util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(encryptedData.length / blockSize);
  //   var leftOverbytes = encryptedData.length % blockSize;
  //   var decryptedData = "";
  //   
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ofb.updateDecrypt(encryptedData.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ofb.updateDecrypt(encryptedData.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ofb.finalDecrypt();
  // 
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
  //   test.done();
  // },
});