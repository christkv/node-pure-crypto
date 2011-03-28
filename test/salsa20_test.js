require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Salsa20 = require('salsa20').Salsa20,
  ECBMode = require('ecb').ECBMode,
  OFBMode = require('ofb').OFBMode,
  CBCMode = require('cbc').CBCMode,
  CFBMode = require('cfb').CFBMode,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Salsa20 tests");

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

suite.addTests({  
  "Test Salsa20 Vectors":function(assert, finished) {
    // var keys = ["00000000000000000000000000000000", "00000000000000000000000000000000",
    //   "9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419",
    //   "000000000000000000000000000000000000000000000000", "EFA71F788965BD4453F860178FC191010000000000000000",
    //   "88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44",
    //   "0000000000000000000000000000000000000000000000000000000000000000",
    //   "D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F"];
    // var pts = ["00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A",
    //   "D491DB16E7B1C39E86CB086B789F5419", "019F9809DE1711858FAAC3A3BA20FBC3",
    //   "00000000000000000000000000000000", "88B2B2706B105E36B446BB6D731A1E88",
    //   "39DA69D6BA4997D585B6DC073CA341B2", "00000000000000000000000000000000",
    //   "90AFE91BB288544F2C32DC239B2635E6"];
    // var cts = ["9F589F5CF6122C32B6BFEC2F2AE8C35A", "D491DB16E7B1C39E86CB086B789F5419",
    //   "019F9809DE1711858FAAC3A3BA20FBC3", "6363977DE839486297E661C6C9D668EB",
    //   "EFA71F788965BD4453F860178FC19101", "39DA69D6BA4997D585B6DC073CA341B2",
    //   "182B02D81497EA45F9DAACDC29193A65", "57FF739D4DC92C1BD7FC01700CC8216F",
    //   "6CB4561C40BF0A9705931CB6D408E7FA"];
      
    // Test vectors
    for(var i = 0; i < testCases.length; i++) {
      var zero = testCases[i].zero;
      var key = testCases[i].key;
      var iv = testCases[i].iv;
      var stream = testCases[i].stream;
      var xor = testCases[i].xor;
      var pt = zeroedData(zero);
            
      // Encrypt the data and verify
      var salsa = new Salsa20(key, iv);
      var encrypted = [];
      var chunkindex = 0;

      // Encrypt in chunks of data
      for(var j = 0, k = 0, l = 64, m = zero; k < m; j++) {
        l += j;
        if((k + l) > m) {
          l = m - k;
        }
        var crypted = salsa.encrypt(pt.slice(k, k+l));
        encrypted = encrypted.concat(crypted);
        k += l;
      }

      // Assert correctness of encryption
      for(var i = 0; i < stream.length; i++) {
        var chunk = stream[i].chunk;
        var start = stream[i].start;
        var len = stream[i].len;
        assert.deepEqual(chunk, encrypted.slice(start, start + len));
      }

      // // Decrypt data and verify
      // salsa = new Salsa20(key);
      // var decrypted = salsa.decrypt(encrypted);
      // assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  

  // "Node Compatibility Tests":function(assert, finished) {
  //   var key = "00112233445566778899AABBCCDDEEFFFFEEDDCCBBAA99887766554433221100";
  //   var pt =  "02132435465768798a9bacbdcedfe0f1";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //     
  //   // OFB Mode
  //   var ofb = new OFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //     
  //   var ofb = new OFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(src);
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CBC Mode
  //   var cbc = new CBCMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = cbc.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var cbc = new CBCMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = cbc.decrypt(src);    
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // ECB Mode
  //   var ecb = new ECBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ecb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ecb = new ECBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ecb.decrypt(src);    
  //   assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   
  //   // CFB Mode
  //   var ofb = new CFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   
  //   var ofb = new CFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   var ofb = new OFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
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
  //   ofb = new OFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   src = ofb.encrypt(util.binaryStringToArray(data));
  //   assert.deepEqual(src, util.binaryStringToArray(encryptedData));
  //       
  //   // Clean cbc instance
  //   ofb = new OFBMode(new Salsa20(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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

var testCases = [
{
  zero:512,
	key: [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
	iv: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
	stream: [
	  {
	    start:0, 
	    len:64, 
	    chunk:[
				0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0, 0x9A, 0x31, 0x02, 0x20, 0x50, 0x85, 0x99, 0x36, 
				0xDA, 0x52, 0xFC, 0xEE, 0x21, 0x80, 0x05, 0x16, 0x4F, 0x26, 0x7C, 0xB6, 0x5F, 0x5C, 0xFD, 0x7F, 
				0x2B, 0x4F, 0x97, 0xE0, 0xFF, 0x16, 0x92, 0x4A, 0x52, 0xDF, 0x26, 0x95, 0x15, 0x11, 0x0A, 0x07, 
				0xF9, 0xE4, 0x60, 0xBC, 0x65, 0xEF, 0x95, 0xDA, 0x58, 0xF7, 0x40, 0xB7, 0xD1, 0xDB, 0xB0, 0xAA, 
			]
	  },  	  
	  {
	    start: 192,
	    len:64, 
	    chunk:[
				0xDA, 0x9C, 0x15, 0x81, 0xF4, 0x29, 0xE0, 0xA0, 0x0F, 0x7D, 0x67, 0xE2, 0x3B, 0x73, 0x06, 0x76, 
				0x78, 0x3B, 0x26, 0x2E, 0x8E, 0xB4, 0x3A, 0x25, 0xF5, 0x5F, 0xB9, 0x0B, 0x3E, 0x75, 0x3A, 0xEF, 
				0x8C, 0x67, 0x13, 0xEC, 0x66, 0xC5, 0x18, 0x81, 0x11, 0x15, 0x93, 0xCC, 0xB3, 0xE8, 0xCB, 0x8F, 
				0x8D, 0xE1, 0x24, 0x08, 0x05, 0x01, 0xEE, 0xEB, 0x38, 0x9C, 0x4B, 0xCB, 0x69, 0x77, 0xCF, 0x95, 
      ]
	  },  	  
	  {
	    start: 256,
	    len:64, 
	    chunk:[
				0x7D, 0x57, 0x89, 0x63, 0x1E, 0xB4, 0x55, 0x44, 0x00, 0xE1, 0xE0, 0x25, 0x93, 0x5D, 0xFA, 0x7B, 
				0x3E, 0x90, 0x39, 0xD6, 0x1B, 0xDC, 0x58, 0xA8, 0x69, 0x7D, 0x36, 0x81, 0x5B, 0xF1, 0x98, 0x5C, 
				0xEF, 0xDF, 0x7A, 0xE1, 0x12, 0xE5, 0xBB, 0x81, 0xE3, 0x7E, 0xCF, 0x06, 0x16, 0xCE, 0x71, 0x47, 
				0xFC, 0x08, 0xA9, 0x3A, 0x36, 0x7E, 0x08, 0x63, 0x1F, 0x23, 0xC0, 0x3B, 0x00, 0xA8, 0xDA, 0x2F, 
      ]
	  },  	  
	  {
	    start: 448,
	    len:64, 
	    chunk:[
				0xB3, 0x75, 0x70, 0x37, 0x39, 0xDA, 0xCE, 0xD4, 0xDD, 0x40, 0x59, 0xFD, 0x71, 0xC3, 0xC4, 0x7F, 
				0xC2, 0xF9, 0x93, 0x96, 0x70, 0xFA, 0xD4, 0xA4, 0x60, 0x66, 0xAD, 0xCC, 0x6A, 0x56, 0x45, 0x78, 
				0x33, 0x08, 0xB9, 0x0F, 0xFB, 0x72, 0xBE, 0x04, 0xA6, 0xB1, 0x47, 0xCB, 0xE3, 0x8C, 0xC0, 0xC3, 
				0xB9, 0x26, 0x7C, 0x29, 0x6A, 0x92, 0xA7, 0xC6, 0x98, 0x73, 0xF9, 0xF2, 0x63, 0xBE, 0x97, 0x03, 
      ]
	  },  	  
	],
  xor: [
		0xF7, 0xA2, 0x74, 0xD2, 0x68, 0x31, 0x67, 0x90, 0xA6, 0x7E, 0xC0, 0x58, 0xF4, 0x5C, 0x0F, 0x2A, 
		0x06, 0x7A, 0x99, 0xFC, 0xDE, 0x62, 0x36, 0xC0, 0xCE, 0xF8, 0xE0, 0x56, 0x34, 0x9F, 0xE5, 0x4C, 
		0x5F, 0x13, 0xAC, 0x74, 0xD2, 0x53, 0x95, 0x70, 0xFD, 0x34, 0xFE, 0xAB, 0x06, 0xC5, 0x72, 0x05, 
		0x39, 0x49, 0xB5, 0x95, 0x85, 0x74, 0x21, 0x81, 0xA5, 0xA7, 0x60, 0x22, 0x3A, 0xFA, 0x22, 0xD4, 
  ]
}];