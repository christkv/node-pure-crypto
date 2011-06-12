require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  Seed = require('symmetric/block/seed').Seed,
  ECBMode = require('symmetric/block/ecb').ECBMode,
  OFBMode = require('symmetric/block/ofb').OFBMode,
  CBCMode = require('symmetric/block/cbc').CBCMode,
  CFBMode = require('symmetric/block/cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

// AlgorithmType: SymmetricCipher
// Name: SEED/ECB
// Source: RFC 4269
// Key:        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
// Plaintext:  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
// Ciphertext: 5E BA C6 E0 05 4E 16 68 19 AF F1 CC 6D 34 6C DB
// Test: Encrypt
// Key:        00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
// Plaintext:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
// Ciphertext: C1 1F 22 F2 01 40 50 50 84 48 35 97 E4 37 0F 43
// Test: Encrypt
// Key:        47 06 48 08 51 E6 1B E8 5D 74 BF B3 FD 95 61 85
// Plaintext:  83 A2 F8 A2 88 64 1F B9 A4 E9 A5 CC 2F 13 1C 7D
// Ciphertext: EE 54 D1 3E BC AE 70 6D 22 6B C3 14 2C D4 0D 4A
// Test: Encrypt
// Key:        28 DB C3 BC 49 FF D8 7D CF A5 09 B1 1D 42 2B E7
// Plaintext:  B4 1E 6B E2 EB A8 4A 14 8E 2E ED 84 59 3C 5E C7
// Ciphertext: 9B 9B 7B FC D1 81 3C B9 5D 0B 36 18 F4 0F 51 22
// Test: Encrypt

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test Seed Vectors":function(test) {
    var keys = ["00000000000000000000000000000000", "000102030405060708090A0B0C0D0E0F",
      "4706480851E61BE85D74BFB3FD956185", "28DBC3BC49FFD87DCFA509B11D422BE7"];
    var pts = ["000102030405060708090A0B0C0D0E0F", "00000000000000000000000000000000",
      "83A2F8A288641FB9A4E9A5CC2F131C7D", "B41E6BE2EBA84A148E2EED84593C5EC7"];
    var cts = ["5EBAC6E0054E166819AFF1CC6D346CDB", "C11F22F20140505084483597E4370F43",
      "EE54D13EBCAE706D226BC3142CD40D4A", "9B9B7BFCD1813CB95D0B3618F40F5122"];
    
    var keys = ["4706480851E61BE85D74BFB3FD956185"];
    var pts = ["83A2F8A288641FB9A4E9A5CC2F131C7D"];
    var cts = ["EE54D13EBCAE706D226BC3142CD40D4A"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var seed = new Seed(key);
      var encrypted = seed.encrypt(pt);
      test.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      seed = new Seed(key);
      var decrypted = seed.decrypt(encrypted);
      test.deepEqual(util.hexStringToBinaryArray(pts[i]), decrypted);
    }
      
    test.done();
  },  

  "Node Compatibility Tests":function(test) {
    var key = "00000000000000000000000000000000";
    var pt =  "000102030405060708090A0B0C0D0E0F";
    // Encrypt using the pure js library    
    var iv = "00010203040506070001020304050607";
  
    // OFB Mode
    var cipher = crypto.createCipheriv("seed-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("seed-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    var ofb = new OFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
      
    var ofb = new OFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
    
    test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    
    // CBC Mode
    var cipher = crypto.createCipheriv("seed-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("seed-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    var cbc = new CBCMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    var cbc = new CBCMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = cbc.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
    
    test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    
    // ECB Mode
    var cipher = crypto.createCipheriv("seed-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("seed-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    var ecb = new ECBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
    test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
    
    var ecb = new ECBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
    
    test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    
    // CFB Mode
    var cipher = crypto.createCipheriv("seed-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("seed-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    var ofb = new CFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    
    var ofb = new CFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
    
    test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    test.done();    
  },
  
  "Streaming api test":function(test) {
    var key = "4706480851E61BE85D74BFB3FD956185";
    // Encrypt using the pure js library    
    var iv = "00010203040506070001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
  
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("seed-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
    
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    test.deepEqual(b, a);
  
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("seed-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean cbc instance
    ofb = new OFBMode(new Seed(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += ofb.finalDecrypt();
      
    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    test.deepEqual(b, a);    
    test.done();
  },    
});