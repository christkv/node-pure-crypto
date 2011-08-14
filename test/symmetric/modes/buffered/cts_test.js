require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../../deps/nodeunit'),
  SkipJack = require('symmetric/block/skipjack').SkipJack,
  DES = require('symmetric/block/des').DES,
  CBC = require('symmetric/modes/cbc').CBC,
  CTS = require('symmetric/modes/buffered/cts').CTS,
  crypto = require('crypto'),
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

  "CTS with DES and no IV":function(test) {
    var key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    var pt = util.hexStringToBinaryArray("4e6f7720697320746865207420");
    var ct = util.hexStringToBinaryArray("9952f131588465033fa40e8a98");
    
    var cipher = new DES();
    var cts = new CTS(cipher);
    var out = new Array(pt.length);
    
    // Init with no IV
    cts.init(true, false, key);
    // Encrypt
    var len = cts.processBytes(pt, 0, pt.length, out, 0);
    cts.doFinal(out, len);
    // Test
    test.deepEqual(ct, out);
    
    // Finished up result
    var out2 = new Array(pt.length);
    // Init for decryption
    cts.init(false, false, key);
    // Decrypt
    var len = cts.processBytes(out, 0, out.length, out2, 0);
    cts.doFinal(out2, len);
    // Test
    test.deepEqual(pt, out2);
    test.done();
  },
  
  "CTS with CBC/DES and IV":function(test) {
    var key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    var pt = util.hexStringToBinaryArray("4e6f7720697320746865207420");
    var ct = util.hexStringToBinaryArray("358f84d01eb42988dc34efb994");
    var iv = [1, 2, 3, 4, 5, 6, 7, 8];
  
    // Set up cipher chain
    var cipher = new DES();
    var cbc = new CBC(cipher);
    var cts = new CTS(cbc);
    var out = new Array(pt.length);
    
    // Init with no IV
    cts.init(true, true, iv, key);
    // Encrypt
    var len = cts.processBytes(pt, 0, pt.length, out, 0);
    cts.doFinal(out, len);
    // Test
    test.deepEqual(ct, out);
  
    // Finished up result
    var out2 = new Array(pt.length);
    // Init for decryption
    cts.init(false, true, iv, key);
    // Decrypt
    var len = cts.processBytes(out, 0, out.length, out2, 0);
    cts.doFinal(out2, len);
    // Test
    test.deepEqual(pt, out2);
    test.done();
  },

  "CTS with CBC/SkipJack and IV":function(test) {
    var key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xee, 0xff];
    var pt = util.hexStringToBinaryArray("000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f0aaa");
    var ct = util.hexStringToBinaryArray("170171cfad3f04530c509b0c1f0be0aefbd45a8e3755a873bff5ea198504b71683c6");
    var iv = [1, 2, 3, 4, 5, 6, 7, 8];

    // Set up cipher chain
    var cipher = new SkipJack();
    var cbc = new CBC(cipher);
    var cts = new CTS(cbc);
    var out = new Array(pt.length);
    
    // Init with no IV
    cts.init(true, true, iv, key);
    // Encrypt
    var len = cts.processBytes(pt, 0, pt.length, out, 0);
    cts.doFinal(out, len);
    
    test.deepEqual(ct, out);

    // Test
    test.deepEqual(ct, out);
    
    // Finished up result
    var out2 = new Array(pt.length);
    // Init for decryption
    cts.init(false, true, iv, key);
    // Decrypt
    var len = cts.processBytes(out, 0, out.length, out2, 0);
    cts.doFinal(out2, len);
    // Test
    test.deepEqual(pt, out2);
    test.done();
  },
    
  // "Node Compatibility Tests":function(test) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4";         
  //   var pt = "6bc1bee22e409f96e93d7e117393172a" + 
  //      "ae2d8a571e03ac9c9eb76fac45af8e51" + 
  //      "30c81c46a35ce411e5fbc1191a0a52ef" + 
  //      "f69f2445df4f9b17ad2b417be66c3710";
  //   var ct = "DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471";
  // 
  //   // Encrypt using the pure js library    
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cfb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.hexStringToBinaryArray(ct), src);
  //   
  //   // Encrypt using the node.js crypto library
  //   var cipher = crypto.createCipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   // Compare the two encrypted contents
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   // Decrypt each others output
  //   var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cfb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');
  //     
  //   // Compare the decrypted content
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs)
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "603deb1015ca71be2b73aef0857d7781" + 
  //      "1f352c073b6108d72d9810a30914dff4";         
  //   // 5K of random data
  //   var data = randomdata(33);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var iv = "000102030405060708090a0b0c0d0e0f";
  //   var cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += cfb.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += cfb.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += cfb.finalEncrypt();
  //     
  //   // Encrypt using node.js to ensure have have the same
  //   var cipher = crypto.createCipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  //   
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   test.deepEqual(b, a);
  //     
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("aes-256-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   cfb = new CFBMode(new AESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
  //   var leftOverbytes = nodejsEncrypted.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {  
  //     decryptedData += cfb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += cfb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += cfb.finalDecrypt();
  //     
  //   // Verify encryption
  //   var a = util.binaryStringToArray(decryptedNode);    
  //   var b = util.binaryStringToArray(decryptedData);    
  //   // Verify the decryption against node.js
  //   test.deepEqual(b, a);    
  //   test.done();
  // },  
});

















