require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Camellia = require('block/camellia').Camellia,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  CFB8Mode = require('block/cfb8').CFB8Mode,
  NullPad = require('padding/null').NullPad,
  util = require('utils'),
  Long = require('long').Long,
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Camellia tests");

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

var xorDigest = function(encrypted, out) {
  for(var i = 0; i < encrypted.length; i++) {
    out[i % out.length] = Long.fromNumber(out[i % out.length] ^ encrypted[i]).getLowBitsUnsigned();
  }  
  return out;
}

suite.addTests({  
  "Test Camellia Vectors":function(assert, finished) {
    var keys = ["00000000000000000000000000000000", "80000000000000000000000000000000", "0123456789abcdeffedcba9876543210",
      "0123456789abcdeffedcba98765432100011223344556677", "000000000000000000000000000000000000000000000000",
      "949494949494949494949494949494949494949494949494",
      "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
      "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
      "0303030303030303030303030303030303030303030303030303030303030303"]
    var pts = ["80000000000000000000000000000000", "00000000000000000000000000000000", "0123456789abcdeffedcba9876543210",
      "0123456789abcdeffedcba9876543210", "00040000000000000000000000000000",
      "636EB22D84B006381235641BCF0308D2",
      "0123456789abcdeffedcba9876543210",
      "057764FE3A500EDBD988C5C3B56CBA9A",
      "7968B08ABA92193F2295121EF8D75C8A"];
    var cts = ["07923A39EB0A817D1C4D87BDB82D1F1C", "6C227F749319A3AA7DA235A9BBA05A2C", "67673138549669730857065648eabe43",
      "b4993401b3e996f84ee5cee7d79b09b9", "9BCA6C88B928C1B0F57F99866583A9BC",
      "94949494949494949494949494949494",
      "9acc237dff16d76c20ef7c919e3a7509",
      "4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A4A",
      "03030303030303030303030303030303"];

    // var keys = ["0123456789abcdeffedcba98765432100011223344556677"]
    // var pts = ["0123456789abcdeffedcba9876543210"];
    // var cts = ["b4993401b3e996f84ee5cee7d79b09b9"];

    for(var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var pt = pts[i];
      var ct = cts[i];
      // Encrypt using the purejs librarie's streaming api in 1024 blocks
      var camellia = new Camellia(util.hexStringToBinaryArray(key));
      // Encrypt the data and verify
      var encrypted = [];
      var pt = util.hexStringToBinaryArray(pt);
      var zero = pt.length;
      
      encrypted = camellia.encrypt(pt.slice(0))
      assert.deepEqual(util.hexStringToBinaryArray(ct), encrypted)

      var camellia = new Camellia(util.hexStringToBinaryArray(key));
      var decrypted = camellia.decrypt(encrypted);
      assert.deepEqual(pt, decrypted)      
    }

    finished();
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "546d203368656c326973652073736e62206167796967747473656865202c3d73";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 16;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new Camellia(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
    ofb = new OFBMode(new Camellia(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    assert.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new Camellia(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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