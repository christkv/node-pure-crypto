require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  RC6 = require('rc6').RC6,
  ECBMode = require('ecb').ECBMode,
  OFBMode = require('ofb').OFBMode,
  CBCMode = require('cbc').CBCMode,
  CFBMode = require('cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("RC6 tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test RC6 Vectors":function(assert, finished) {
    // 00000000000000000000000000000000
    //   00000000000000000000000000000000  8FC3A53656B1F778C129DF4E9848A41E
    // 
    // 0123456789ABCDEF0112233445566778
    //   02132435465768798A9BACBDCEDFE0F1  524E192F4715C6231F51F6367EA43F18
    // 
    // 000000000000000000000000000000000000000000000000
    //   00000000000000000000000000000000  6cd61bcb190b30384e8a3f168690ae82
    // 
    // 0123456789abcdef0112233445566778899aabbccddeeff0
    //   02132435465768798a9bacbdcedfe0f1  688329d019e505041e52e92af95291d4
    // 
    // 0000000000000000000000000000000000000000000000000000000000000000
    //   00000000000000000000000000000000  8f5fbd0510d15fa893fa3fda6e857ec2
    // 
    // 0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe
    //   02132435465768798a9bacbdcedfe0f1  c8241816f0d7e48920ad16a1674e5d48

    // var keys = ["0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe", "0000000000000000000000000000000000000000000000000000000000000000",
    //   "0123456789abcdef0112233445566778899aabbccddeeff0", "000000000000000000000000000000000000000000000000",
    //   "0123456789ABCDEF0112233445566778", "00000000000000000000000000000000"];
    // var pts = ["02132435465768798a9bacbdcedfe0f1", "00000000000000000000000000000000",
    //   "02132435465768798a9bacbdcedfe0f1", "00000000000000000000000000000000",
    //   "02132435465768798A9BACBDCEDFE0F1", "00000000000000000000000000000000"];
    // var cts = ["c8241816f0d7e48920ad16a1674e5d48", "8f5fbd0510d15fa893fa3fda6e857ec2",
    //   "8f5fbd0510d15fa893fa3fda6e857ec2", "6cd61bcb190b30384e8a3f168690ae82",
    //   "524E192F4715C6231F51F6367EA43F18", "8FC3A53656B1F778C129DF4E9848A41E"];

    var keys = ["0123456789abcdef0112233445566778899aabbccddeeff01032547698badcfe"];
    var pts = ["02132435465768798a9bacbdcedfe0f1"];
    var cts = ["c8241816f0d7e48920ad16a1674e5d48"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var rc6 = new RC6(key);
      var encrypted = rc6.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // // Decrypt data and verify
      // rc6 = new RC6(key);
      // var decrypted = rc6.decrypt(encrypted);
      // assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  

  // "Node Compatibility Tests":function(assert, finished) {
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
  //   var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CBC Mode
  //   var cipher = crypto.createCipheriv("cast5-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var cbc = new CBCMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var cbc = new CBCMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // ECB Mode
  //   var cipher = crypto.createCipheriv("cast5-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ecb = new ECBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ecb = new ECBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  //   
  //   assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CFB Mode
  //   var cipher = crypto.createCipheriv("cast5-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("cast5-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new CFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var key = "0123456712345678234567893456789A";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   assert.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("cast5-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   ofb = new OFBMode(new RC6(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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