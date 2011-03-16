require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Serpent = require('serpent').Serpent,
  ECBMode = require('ecb').ECBMode,
  OFBMode = require('ofb').OFBMode,
  CBCMode = require('cbc').CBCMode,
  CFBMode = require('cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Serpent tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test Serpent Vectors":function(assert, finished) {
    var keys = ["00000000000000000000000000000000", "00000000000000000000000000000000", 
      "FFEEDDCCBBAA99887766554433221100", "FFEEDDCCBBAA99887766554433221100",
      "000000000000000000000000000000000000000000000000", "8899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100",
      "8899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100"];
    var pts = ["D29D576FCEA3A3A7ED9099F29273D78E", "D29D576FCEA3A3A7ED9099F26D8C2871",
      "1032547698BADCFEEFCDAB8967452301", "145F0B8B663176B95DCAB7E9DCD5CC24",
      "D29D576FCEABA3A7ED9899F2927BD78E", "1032547698BADCFEEFCDAB8967452301",
      "B2696BD0D98C17953E4239225D27202C", "92074732D84E1841A013A0034C52BF50",
      "1032547698BADCFEEFCDAB8967452301"];
    var cts = ["B2288B968AE8B08648D1CE9606FD992D", "563A8403FF5309D62370B1DCF5A11EDD",
      "D5BAA00A4BB9D8A7C981C8DC90D89D92", "1032547698BADCFEEFCDAB8967452301",
      "130E353E1037C22405E8FAEFB2C3C3E9", "DA860842B720802BF404A4C71034879A",
      "1032547698BADCFEEFCDAB8967452301", "81C4EB7B8AD9A8D0F2AA5D7BD626B560",
      "93DF9A3CAFE387BD999EEBE393A17FCA"];
    
    // var keys = ["00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100"];
    // var pts = ["1032547698BADCFEEFCDAB8967452301"];
    // var cts = ["93DF9A3CAFE387BD999EEBE393A17FCA"];

    var keys = ["00000000000000000000000000000000"];
    var pts = ["D29D576FCEA3A3A7ED9099F29273D78E"];
    var cts = ["B2288B968AE8B08648D1CE9606FD992D"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var serpent = new Serpent(key);
      var encrypted = serpent.encrypt(pt);
      // assert.deepEqual(ct, encrypted);
      // 
      // // Decrypt data and verify
      // serpent = new Serpent(key);
      // var decrypted = serpent.decrypt(encrypted);
      // assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  

  // "Node Compatibility Tests":function(assert, finished) {
  //   var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
  //   var pt =  "02132435465768798a9bacbdcedfe0f1";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //     
  //   // OFB Mode
  //   var ofb = new OFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //     
  //   var ofb = new OFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CBC Mode
  //   var cbc = new CBCMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var cbc = new CBCMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(src);    
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // ECB Mode
  //   var ecb = new ECBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ecb = new ECBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(src);    
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CFB Mode
  //   var ofb = new CFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   finished();    
  // },
  // 
  // "Streaming api test":function(assert, finished) {
  //   var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   // Single pass encryption
  //   ofb = new OFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   assert.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new Serpent(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(src.length / blockSize);
  //   var leftOverbytes = src.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ofb.updateDecrypt(util.arrayToBinaryString(src).substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ofb.finalDecrypt();
  // 
  //   // Compare
  //   assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedData))    
  //   finished();
  // },
});