require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Gost28147 = require('block/gost28147').Gost28147,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  CFB8Mode = require('block/cfb8').CFB8Mode,
  NullPad = require('padding/null').NullPad,
  util = require('utils'),
  Long = require('long').Long,
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Gost28147 tests");

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
  "Test Gost28147 Vectors":function(assert, finished) {
    var keys = ["546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73"];
    var pts = ["0000000000000000", "0000000000000000", "0000000000000000"];
    var cts = ["1b0bbc32cebcab42", "ADE405529820381C", "B4AF4895149B9048"];
    var sboxs = [Gost28147.Sbox_Default, Gost28147.ESbox_A, Gost28147.ESbox_B]

    for(var i = 0; i < keys.length; i++) {
    // for(var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var pt = pts[i];
      var ct = cts[i];
      var sbox = sboxs[i];
      // Encrypt using the purejs librarie's streaming api in 1024 blocks
      var gost28147 = new Gost28147(util.hexStringToBinaryArray(key), sbox);
      // Encrypt the data and verify
      var encrypted = [];
      var pt = util.hexStringToBinaryArray(pt);
      var zero = pt.length;
      
      encrypted = gost28147.encrypt(pt.slice(0))
      assert.deepEqual(util.hexStringToBinaryArray(ct), encrypted)

      var gost28147 = new Gost28147(util.hexStringToBinaryArray(key), sbox);
      var decrypted = gost28147.decrypt(encrypted);
      assert.deepEqual(pt, decrypted)      
    }

    finished();
  },

  "Test Gost28147 Vectors Padding":function(assert, finished) {
    var keys = ["00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
      "aafd12f659cae63489b479e5076ddec2f06cb58faafd12f659cae63489b479e5", 
      "546d203368656c326973652073736e62206167796967747473656865202c3d73", 
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73",
      "546d203368656c326973652073736e62206167796967747473656865202c3d73"];
    var ivs = ["1234567890abcdef", "aafd12f659cae634", 
      "1234567890abcdef", "1234567890abcdef", "1234567890abcdef",
      "1234567890abcdef", "1234567890abcdef", "1234567890abcdef",
      "1234567890abcdef", "1234567890abcdef"]
    var pts = ["bc350e71aac5f5c2", "000102030405060708090a0b0c0d0e0fff0102030405060708090a0b0c0d0e0f",
      "0000000000000000", "0000000000000000", "0000000000000000",
      "0000000000000000", "0000000000000000", "0000000000000000",
      "0000000000000000", "0000000000000000"];
    var cts = ["d35ab653493b49f5", "29b7083e0a6d955ca0ec5b04fdb4ea41949f1dd2efdf17baffc1780b031f3934",
      "b587f7a0814c911d", "c41009dba22ebe35", "e8287f53f991d52b",
      "80d8723fcd3aba28", "739f6f95068499b5", "4663f720f4340f57",
      "5bb0a31d218ed564", "c3af96ef788667c5"];
    var sboxs = [Gost28147.Sbox_Default, Gost28147.Sbox_Default, 
      Gost28147.DSbox_Test, Gost28147.ESbox_A, Gost28147.ESbox_Test, 
      Gost28147.ESbox_B, Gost28147.ESbox_C, Gost28147.ESbox_D,
      Gost28147.DSbox_A, TestSBox]
    var wrappers = ["cbc", "cfb", 
      "cfb", "cfb", "cfb", 
      "cfb8", "cfb8", "cfb8",
      "cfb8", "cfb8"]
  
    for(var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var iv = ivs[i];
      var pt = pts[i];
      var ct = cts[i];
      var sbox = sboxs[i];
      var wrapper = wrappers[i];
      var mode = null;
  
      // Encrypt using the purejs librarie's streaming api in 1024 blocks
      var gost28147 = new Gost28147(util.hexStringToBinaryArray(key), sbox);      
      if(wrapper == "cbc") {
        mode = new CBCMode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      } else if(wrapper == "cfb") {
        mode = new CFBMode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      } else if(wrapper == "cfb8") {
        mode = new CFB8Mode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      }
      
      // Encrypt the data and verify
      var encrypted = [];
      var pt = util.hexStringToBinaryArray(pt);
      var zero = pt.length;
  
      encrypted = mode.encrypt(pt.slice(0));
      assert.deepEqual(util.hexStringToBinaryArray(ct), encrypted);
  
      var gost28147 = new Gost28147(util.hexStringToBinaryArray(key), sbox);
      if(wrapper == "cbc") {
        mode = new CBCMode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      } else if(wrapper == "cfb") {
        mode = new CFBMode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      } else if(wrapper == "cfb8") {
        mode = new CFB8Mode(gost28147, new NullPad(), util.hexStringToBinaryArray(iv));
      }
      
      var decrypted = mode.decrypt(encrypted);
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
    var ofb = new OFBMode(new Gost28147(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
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
    ofb = new OFBMode(new Gost28147(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    src = ofb.encrypt(util.binaryStringToArray(data));
    assert.deepEqual(src, util.binaryStringToArray(encryptedData));
        
    // Clean cbc instance
    ofb = new OFBMode(new Gost28147(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
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

var TestSBox = [
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
        0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
        0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
        0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0,
        0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xA,0xB,0xC,0xD,0xE,0xF,
        0xF,0xE,0xD,0xC,0xB,0xA,0x9,0x8,0x7,0x6,0x5,0x4,0x3,0x2,0x1,0x0
];
