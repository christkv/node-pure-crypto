require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  IDEA = require('idea').IDEA,
  ECBMode = require('ecb').ECBMode,
  OFBMode = require('ofb').OFBMode,
  CBCMode = require('cbc').CBCMode,
  CFBMode = require('cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("IDEA tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  // "Test IDEA Vectors":function(assert, finished) {
  //   var keys = ["00010002000300040005000600070008", "00010002000300040005000600070008",
  //     "00010002000300040005000600070008", "00010002000300040005000600070008",
  //     "00010002000300040005000600070008", "00010002000300040005000600070008",
  //     "00010002000300040005000600070008", "0005000A000F00140019001E00230028",
  //     "006400C8012C019001F4025802BC0320", "9D4075C103BC322AFB03E7BE6AB30006",
  //     "3A984E2000195DB32EE501C8C47CEA60", "00010002000300040005000600070008"]
  //     
  //     //,
  //     // "3A984E2000195DB32EE501C8C47CEA60",
  //     // ""];
  //   var pts = ["0000000100020003", "0102030405060708", "0019324B647D96AF",
  //     "F5202D5B9C671B08", "FAE6D2BEAA96826E", "0A141E28323C4650",
  //     "050A0F14191E2328", "0102030405060708", "05320A6414C819FA",
  //     "0808080808080808", "0102030405060708", "0000000100020003"]
  //     
  //     //, "0102030405060708",
  //     // ""];
  //   var cts = ["11FBED2B01986DE5", "540E5FEA18C2F8B1", "9F0A0AB6E10CED78",
  //     "CF18FD7355E2C5C5", "85DF52005608193D", "2F7DE750212FB734",
  //     "7B7314925DE59C09", "3EC04780BEFF6E20", "65BE87E7A2538AED",
  //     "F5DB1AC45E5EF9F9", "97BCD8200780DA86", "11FBED2B01986DE5"]
  //         
  //   // Test vectors
  //   for(var i = 0; i < keys.length; i++) {
  //     var key = util.hexStringToBinaryArray(keys[i]);
  //     var pt = util.hexStringToBinaryArray(pts[i]);
  //     var ct = util.hexStringToBinaryArray(cts[i]);
  //     
  //     // Encrypt the data and verify
  //     var idea = new IDEA(key);
  //     var encrypted = idea.encrypt(pt);
  //     assert.deepEqual(ct, encrypted);
  // 
  //     // Decrypt data and verify
  //     idea = new IDEA(key);
  //     var decrypted = idea.decrypt(encrypted);
  //     assert.deepEqual(pt, decrypted);
  //   }
  //     
  //   finished();
  // },  
  
  "Encrypt a long file":function(assert, finished) {
    // 5K of random data
    var data = util.binaryStringToArray(randomdata(1024));
    var key = "00010002000300040005000600070008";
    var encryptedData = [];

    // Encrypt the data and verify
    var idea = new IDEA(key);
    
    var numberOfBlocks = data.length / idea.getBlockSize();
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData = encryptedData.concat(idea.encrypt(data, (i * idea.getBlockSize())));
    }
    
    // var encrypted = idea.encrypt(pt);
    
    // debug("-----------------------------------------------------------------")
    // debug(encryptedData);
    
    finished();
  }

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
  //   var ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //     
  //   var ofb = new OFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var cbc = new CBCMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var cbc = new CBCMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var ecb = new ECBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ecb = new ECBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var ofb = new CFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new CAST128(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   assert.deepEqual(b, a);    
  //   finished();
  // },    
});