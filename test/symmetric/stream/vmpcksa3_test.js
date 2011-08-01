require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  VMPCKSA3 = require('symmetric/stream/vmpcksa3').VMPCKSA3,
  // ECBMode = require('symmetric/block/ecb').ECBMode,
  // OFBMode = require('symmetric/block/ofb').OFBMode,
  // CBCMode = require('symmetric/block/cbc').CBCMode,
  // CFBMode = require('symmetric/block/cfb').CFBMode,
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

var xorDigest = function(encrypted, out) {
  for(var i = 0; i < encrypted.length; i++) {
    out[i % out.length] = Long.fromNumber(out[i % out.length] ^ encrypted[i]).getLowBitsUnsigned();
  }  
  return out;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test Xstream":function(test) {
    var key = "9661410AB797D8A9EB767C21172DF6C7";
    var iv = "4B5C2F003E67F39557A8D26F3DA2B155";
    var pt = new Array(1000000);
    for(var i = 0; i < 1000000; i++) pt[i] = 0
     // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var vmpcksa3 = new VMPCKSA3();
    vmpcksa3.init(true, util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // Encrypt the data and verify
    var encrypted = [];
    var pt = util.hexStringToBinaryArray(pt);
    var zero = pt.length;

    var encrypted = pt.slice(0);
    vmpcksa3.processBytes(encrypted, 0);

    // tests
    test.equal(0xb6, encrypted[0])
    test.equal(0xeb, encrypted[1])
    test.equal(0xae, encrypted[2])
    test.equal(0xfe, encrypted[3])
    test.equal(0x48, encrypted[252])
    test.equal(0x17, encrypted[253])
    test.equal(0x24, encrypted[254])
    test.equal(0x73, encrypted[255])
    test.equal(0x1d, encrypted[1020])
    test.equal(0xae, encrypted[1021])
    test.equal(0xc3, encrypted[1022])
    test.equal(0x5a, encrypted[1023])
    test.equal(0x1d, encrypted[102396])
    test.equal(0xa7, encrypted[102397])
    test.equal(0xe1, encrypted[102398])
    test.equal(0xdc, encrypted[102399])

     // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var vmpc = new VMPCKSA3();
    vmpc.init(true, util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    // Encrypt the data and verify
    var encrypted = [];
    var pt = util.hexStringToBinaryArray(pt);
    var zero = pt.length;

    var encrypted = pt.slice(0);
    for(var ij = 0; ij < encrypted.length; ij++) {
      encrypted[ij] = vmpc.returnByte(encrypted[ij]);
    }

    test.equal(0xb6, encrypted[0])
    test.equal(0xeb, encrypted[1])
    test.equal(0xae, encrypted[2])
    test.equal(0xfe, encrypted[3])
    test.equal(0x48, encrypted[252])
    test.equal(0x17, encrypted[253])
    test.equal(0x24, encrypted[254])
    test.equal(0x73, encrypted[255])
    test.equal(0x1d, encrypted[1020])
    test.equal(0xae, encrypted[1021])
    test.equal(0xc3, encrypted[1022])
    test.equal(0x5a, encrypted[1023])
    test.equal(0x1d, encrypted[102396])
    test.equal(0xa7, encrypted[102397])
    test.equal(0xe1, encrypted[102398])
    test.equal(0xdc, encrypted[102399])
    
    // Decrypt
    var vmpc = new VMPCKSA3();
    vmpc.init(false, util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
    var decrypted = encrypted.slice(0);
    vmpc.processBytes(decrypted);    
    test.deepEqual(pt, decrypted)
    test.done();
  },
  
  // "Streaming api test":function(test) {
  //   var key = "a6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff88030";
  //   // Encrypt using the pure js library    
  //   var iv = "9e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 64;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += vmpcksa3.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += vmpcksa3.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += vmpcksa3.finalEncrypt();    
  //   
  //   var vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // One bang encryption
  //   var oneTimeEncryptedData = vmpcksa3.encrypt(util.binaryStringToArray(data));
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
  //     
  //   // Convert onetime encrypted data to binary
  //   oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
  //     
  //   // Clean cbc instance
  //   vmpcksa3 = new VMPCKSA3(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
  //   var leftOverbytes = oneTimeEncryptedData.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += vmpcksa3.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += vmpcksa3.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += vmpcksa3.finalDecrypt();
  //     
  //   // Ensure stream is compatible with the onetime encryption    
  //   test.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
  //   test.done();
  // },      
});