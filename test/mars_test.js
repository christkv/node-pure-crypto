require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Mars = require('mars').Mars,
  ECBMode = require('ecb').ECBMode,
  OFBMode = require('ofb').OFBMode,
  CBCMode = require('cbc').CBCMode,
  CFBMode = require('cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Mars tests");

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

suite.addTests({  
  "Test Mars Vectors":function(assert, finished) {
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
    
    // var keys = ["00000000000000000000000000000000"];
    // var pts = ["00000000000000000000000000000000"];
    // var cts = ["DCC07B8DFB0738D6E30A22DFCF27E886"];

    // var keys = ["80000000000000000000000000000000", "00000000000000000000000000000000",
    //   "00000000000000000000000000000000", "CB14A1776ABBC1CDAFE7243DEF2CEA02"]
    // 
    // var pts = ["00000000000000000000000000000000", "00000000000000000000000000000000",
    //   "DCC07B8DFB0738D6E30A22DFCF27E886", "F94512A9B42D034EC4792204D708A69B"]
    // 
    // var cts = ["B3E2AD5608AC1B6733A7CB4FDF8F9952", "DCC07B8DFB0738D6E30A22DFCF27E886",
    //   "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF", "225DA2CB64B73F79069F21A5E3CB8522"]

    // var keys = ["791739A58B04581A93A953A82C10411DD158860838874D95"];
    // var pts = ["6761C42D3E6142D2A84FBFADB383158F"];
    // var cts = ["F706BC0FD97E28B6F1AF4E17D8755FFF"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var mars = new Mars(key);
      var encrypted = mars.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      mars = new Mars(key);
      var decrypted = mars.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  

  // "Node Compatibility Tests":function(assert, finished) {
  //   var key = "00000000000000000000000000000000";
  //   var pt =  "000102030405060708090A0B0C0D0E0F";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  // 
  //   // OFB Mode
  //   var cipher = crypto.createCipheriv("mars-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("mars-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CBC Mode
  //   var cipher = crypto.createCipheriv("mars-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("mars-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var cbc = new CBCMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var cbc = new CBCMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // ECB Mode
  //   var cipher = crypto.createCipheriv("mars-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("mars-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ecb = new ECBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ecb = new ECBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CFB Mode
  //   var cipher = crypto.createCipheriv("mars-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("mars-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new CFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   finished();    
  // },
  // 
  // "Streaming api test":function(assert, finished) {
  //   var key = "4706480851E61BE85D74BFB3FD956185";
  //   // Encrypt using the pure js library    
  //   var iv = "00010203040506070001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var cipher = crypto.createCipheriv("mars-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  //   
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   assert.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("mars-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   ofb = new OFBMode(new Mars(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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
  //   assert.deepEqual(b, a);    
  //   finished();
  // },    
});