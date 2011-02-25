require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  MARC4 = require('marc4').MARC4,
  util = require('utils');  
  
var suite = exports.suite = new TestSuite("MARC4 tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test MARC4 Vectors":function(assert, finished) {
    var keys = ["0123456789ABCDEF", "618A63D2FB"];
    var pts = ["0000000000000000", "DCEE4CF92C"];
    var cts = ["7494C2E7104B0879", "F13829C9DE"];
    var drops = [0, 0];    
  
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var drop = drops[i];
      
      // Encrypt the data and verify
      var marc4 = new MARC4(key, drop);
      var encrypted = marc4.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      marc4 = new MARC4(key, drop);
      var decrypted = marc4.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "DC51C3AC3BFC62F12E3D36FE91281329";
    // var key = [0xDC, 0x51, 0xC3, 0xAC, 0x3B, 0xFC, 0x62, 0xF1, 0x2E, 0x3D, 0x36, 0xFE, 0x91, 0x28, 0x13, 0x29];    
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(5000);
    // Blocksize
    var blockSize = 1536;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var marc4 = new MARC4(util.hexStringToBinaryArray(key));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += marc4.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
      
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += marc4.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += marc4.finalEncrypt();    
    
    // Reinitialize the marc encryptor
    marc4 = new MARC4(util.hexStringToBinaryArray(key));
    // One bang encryption
    var oneTimeEncryptedData = marc4.encrypt(util.binaryStringToArray(data));
    // Ensure stream is compatible with the onetime encryption    
    assert.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
      
    // Convert onetime encrypted data to binary
    oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
      
    // Clean cbc instance
    marc4 = new MARC4(util.hexStringToBinaryArray(key));
    // Split the data
    var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
    var leftOverbytes = oneTimeEncryptedData.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += marc4.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += marc4.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += marc4.finalDecrypt();
      
    // Ensure stream is compatible with the onetime encryption    
    assert.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
    finished();
  },    
});