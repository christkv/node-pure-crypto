require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  VMPCKSA3 = require('stream/vmpcksa3').VMPCKSA3,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils'),
  Long = require('long').Long,
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("VMPCKSA3 tests");

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
  "Test Xstream":function(assert, finished) {
    var key = "9661410AB797D8A9EB767C21172DF6C7";
    var iv = "4B5C2F003E67F39557A8D26F3DA2B155";
    var pt = new Array(1000000);
    for(var i = 0; i < 1000000; i++) pt[i] = 0
     // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // Encrypt the data and verify
    var encrypted = [];
    var pt = util.hexStringToBinaryArray(pt);
    var zero = pt.length;

    // Asserts
    encrypted = vmpcksa3.encrypt(pt.slice(0))
    assert.equal(0xb6, encrypted[0])
    assert.equal(0xeb, encrypted[1])
    assert.equal(0xae, encrypted[2])
    assert.equal(0xfe, encrypted[3])
    assert.equal(0x48, encrypted[252])
    assert.equal(0x17, encrypted[253])
    assert.equal(0x24, encrypted[254])
    assert.equal(0x73, encrypted[255])
    assert.equal(0x1d, encrypted[1020])
    assert.equal(0xae, encrypted[1021])
    assert.equal(0xc3, encrypted[1022])
    assert.equal(0x5a, encrypted[1023])
    assert.equal(0x1d, encrypted[102396])
    assert.equal(0xa7, encrypted[102397])
    assert.equal(0xe1, encrypted[102398])
    assert.equal(0xdc, encrypted[102399])
    
    // Decrypt
    var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    var decrypted = vmpcksa3.decrypt(encrypted);
    assert.deepEqual(pt, decrypted)
    finished();
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "a6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff88030";
    // Encrypt using the pure js library    
    var iv = "9e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 64;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += vmpcksa3.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += vmpcksa3.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += vmpcksa3.finalEncrypt();    
    
    var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // One bang encryption
    var oneTimeEncryptedData = vmpcksa3.encrypt(util.binaryStringToArray(data));
    // Ensure stream is compatible with the onetime encryption    
    assert.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
      
    // Convert onetime encrypted data to binary
    oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
      
    // Clean cbc instance
    vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // Split the data
    var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
    var leftOverbytes = oneTimeEncryptedData.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += vmpcksa3.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += vmpcksa3.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += vmpcksa3.finalDecrypt();
      
    // Ensure stream is compatible with the onetime encryption    
    assert.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
    finished();
  },      
});