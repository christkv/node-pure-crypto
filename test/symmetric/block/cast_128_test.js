require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  CAST128 = require('symmetric/block/cast_128').CAST128,
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

  "Test CAST-128 Vectors":function(test) {
    var keys = ["0123456712", "01234567123456782345", "0123456712345678234567893456789A"];
    var pts = ["0123456789ABCDEF", "0123456789ABCDEF", "0123456789ABCDEF"];
    var cts = ["7AC816D16E9B302E", "EB6A711A2C02271B", "238B4FE5847E44B2"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt data
      var cipher = new CAST128();
      cipher.init(true, key);
      test.equal(8, cipher.processBlock(data, 0, data, 0));  // Destructive to save memory      
      test.deepEqual(ct, data);
      
      // Initialize cipher for decryption
      cipher.init(false, key);
      // Decrypt the encrypted data and compare
      test.equal(8, cipher.processBlock(data, 0, data, 0));
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }
      
    test.done();
  },  

  // "Node Compatibility Tests":function(test) {
  //   var key = "0123456712345678234567893456789A";
  //   var pt =  "0123456789ABCDEF0123456789ABCDEF";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  // 
  //   // OFB Mode
  //   var cipher = crypto.createCipheriv("cast5-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CBC Mode
  //   var cipher = crypto.createCipheriv("cast5-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var cbc = new CBCMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var cbc = new CBCMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // ECB Mode
  //   var cipher = crypto.createCipheriv("cast5-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ecb = new ECBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ecb = new ECBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CFB Mode
  //   var cipher = crypto.createCipheriv("cast5-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new CFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var key = "0123456712345678234567893456789A";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var cipher = crypto.createCipheriv("cast5-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  //   
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   test.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("cast5-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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

