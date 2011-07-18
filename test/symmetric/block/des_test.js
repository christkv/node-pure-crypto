require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  crypto = require('crypto'),
  DES = require('symmetric/block/des').DES,
  util = require('utils');
    
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

  "DES ECB Test Vectors":function(test) {
		var keys = [
		  "3b3898371520f75e", // grabbed from the output of some js implementation out there
		  "10316E028C8F3B4A", // appendix A vector
		  "0101010101010101", // appendix B Table 1, round 0
		  "0101010101010101", // round 1
		  "0101010101010101", // 2
  		"0101010101010101", 
  		"0101010101010101", "0101010101010101", "0101010101010101", "0101010101010101",
  		"0101010101010101", // round 8
  		"8001010101010101", // app B, tbl 2, round 0
  		"4001010101010101", "2001010101010101", "1001010101010101",
  		"0801010101010101", "0401010101010101", "0201010101010101", "0180010101010101",
  		"0140010101010101", // round 8
    ];
    
		var pts = [
      "0000000000000000", // js
      "0000000000000000", // App A
      "8000000000000000", // App B, tbl 1, rnd0
      "4000000000000000", "2000000000000000", "1000000000000000",
      "0800000000000000", // rnd 4
      "0400000000000000", "0200000000000000", "0100000000000000",
      "0080000000000000", // round 8
      "0000000000000000", // App B, tbl2, rnd0
      "0000000000000000", "0000000000000000", "0000000000000000", "0000000000000000",
      "0000000000000000", "0000000000000000", "0000000000000000",
      "0000000000000000", // rnd 8
    ];
    
		var cts = [
      "83A1E814889253E0", // js
      "82DCBAFBDEAB6602", // App A
      "95F8A5E5DD31D900", // App b, tbl 1, rnd 0
      "DD7F121CA5015619", "2E8653104F3834EA", "4BD388FF6CD81D4F", "20B9E767B2FB1456",
      "55579380D77138EF", "6CC5DEFAAF04512F", "0D9F279BA5D87260",
      "D9031B0271BD5A0A", // rnd 8
      "95A8D72813DAA94D", // App B, tbl 2, rnd 0
      "0EEC1487DD8C26D5", "7AD16FFB79C45926", "D3746294CA6A6CF3", "809F5F873C1FD761",
      "C02FAFFEC989D1FC", "4615AA1D33E72F10", "2055123350C00858",
      "DF3B99D6577397C8", // rnd 8
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);

      // Encrypt data
      var cipher = new DES();
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
  
  // "Node Compatibility Tests":function(test) {
  //   var key = "10316E028C8F3B4A";
  //   var pt =  "6bc1bee22e409f96";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  // 
  //   // OFB Mode
  //   var cipher = crypto.createCipheriv("des-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("des-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new OFBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new OFBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //     
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CBC Mode
  //   var cipher = crypto.createCipheriv("des-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("des-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //     
  //   var ofb = new CBCMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new CBCMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //     
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //     
  //   // ECB Mode
  //   var cipher = crypto.createCipheriv("des-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("des-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new ECBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ofb = new ECBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //     
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CFB Mode
  //   var cipher = crypto.createCipheriv("des-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("des-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //     
  //   var ofb = new CFBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //     
  //   var ofb = new CFBMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //     
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "10316E028C8F3B4A";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new CBCMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   // Encrypt using node.js to ensure have have the same
  //   var cipher = crypto.createCipheriv("des-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  //   
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   test.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("des-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   ofb = new CBCMode(new DESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
  //   var leftOverbytes = nodejsEncrypted.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ofb.finalDecrypt();
  //     
  //   // Verify encryption
  //   var a = util.binaryStringToArray(decryptedNode);    
  //   var b = util.binaryStringToArray(decryptedData);    
  //   // Verify the decryption against node.js
  //   test.deepEqual(b, a);    
  //   test.done();
  // },  
});



















