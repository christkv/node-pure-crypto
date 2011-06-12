require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  Mars = require('symmetric/block/mars').Mars,
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

// OTHER TESTS
// Key: 00000000000000000000000000000000   
// Plaintext: 00000000000000000000000000000000   
// Ciphertext: 3FE24DC09173D15F4616A849D396F7E3
// Test: EncryptionMCT
// Key: 00000000000000000000000000000000   
// Plaintext: 24BD3D2FC6FEE152D1D64545E2230584   
// Ciphertext: 00000000000000000000000000000000
// Test: DecryptionMCT
// Key: 000000000000000000000000000000000000000000000000   
// Plaintext: 00000000000000000000000000000000   
// Ciphertext: 34EC834E2F30741ECB476DA7E9662BBD
// Test: EncryptionMCT
// Key: 000000000000000000000000000000000000000000000000   
// Plaintext: 7F27C3397A8CEEF1BDF859459690FEA8   
// Ciphertext: 00000000000000000000000000000000
// Test: DecryptionMCT
// Key: 0000000000000000000000000000000000000000000000000000000000000000   
// Plaintext: 00000000000000000000000000000000   
// Ciphertext: EDE145C10E279501D921C5E3B04420A6
// Test: EncryptionMCT
// Key: 0000000000000000000000000000000000000000000000000000000000000000   
// Plaintext: 95615ADB0DDF6613A5E84F849AC8C00D   
// Ciphertext: 00000000000000000000000000000000
// Test: DecryptionMCT

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test Mars Vectors":function(test) {
    var keys = ["80000000000000000000000000000000", "00000000000000000000000000000000",
      "00000000000000000000000000000000", "CB14A1776ABBC1CDAFE7243DEF2CEA02",
      "86EDF4DA31824CABEF6A4637C40B0BAB", "000000000000000000000000000000000000000000000000",
      "D158860838874D9500000000000000000000000000000000", "791739A58B04581A93A953A82C10411DD158860838874D95",
      "0000000000000000000000000000000000000000000000000000000000000000", "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227",
      ];
    var pts = ["00000000000000000000000000000000", "00000000000000000000000000000000",
      "DCC07B8DFB0738D6E30A22DFCF27E886", "F94512A9B42D034EC4792204D708A69B",
      "4DF955AD5B398D66408D620A2B27E1A9", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "93A953A82C10411DD158860838874D95", "6761C42D3E6142D2A84FBFADB383158F",
      "62E45B4CF3477F1DD65063729D9ABA8F", "1344ABA4D3C44708A8A72116D4F49384",
      ];
    var cts = ["B3E2AD5608AC1B6733A7CB4FDF8F9952", "DCC07B8DFB0738D6E30A22DFCF27E886",
      "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF", "225DA2CB64B73F79069F21A5E3CB8522",
      "A4B737340AE6D2CAFD930BA97D86129F", "97778747D60E425C2B4202599DB856FB",
      "4FA0E5F64893131712F01408D233E9F7", "F706BC0FD97E28B6F1AF4E17D8755FFF",
      "0F4B897EA014D21FBC20F1054A42F719", "458335D95EA42A9F4DCCD41AECC2390D", 
      ];
        
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var mars = new Mars(key);
      var encrypted = mars.encrypt(pt);
      test.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      mars = new Mars(key);
      var decrypted = mars.decrypt(encrypted);
      test.deepEqual(pt = util.hexStringToBinaryArray(pts[i]), decrypted);
    }
      
    test.done();
  },  

  "Node Compatibility Tests":function(test) {
    var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
    var pt =  "02132435465768798a9bacbdcedfe0f1";
    // Encrypt using the pure js library    
    var iv = "00010203040506070001020304050607";
      
    // OFB Mode
    var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
      
    var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(src);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // CBC Mode
    var cbc = new CBCMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
    
    var cbc = new CBCMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = cbc.decrypt(src);    
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // ECB Mode
    var ecb = new ECBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
    
    var ecb = new ECBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ecb.decrypt(src);    
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    
    // CFB Mode
    var ofb = new CFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    
    var ofb = new CFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(src);
    test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    test.done();    
  },
  
  "Streaming api test":function(test) {
    var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
    // Encrypt using the pure js library    
    var iv = "00010203040506070001020304050607";
    // 5K of random data
    var data = randomdata(1025);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
    ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    test.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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
    test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
    test.done();
  },
});