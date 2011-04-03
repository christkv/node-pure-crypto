require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Sosemanuk = require('stream/sosemanuk').Sosemanuk,
  ECBMode = require('block/ecb').ECBMode,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils'),
  Long = require('long').Long,
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("Sosemanuk tests");

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
  "Test Simple Sosemanuk Vector":function(assert, finished) {      
    // Test vectors
    for(var ij = 0; ij < testCases.length; ij++) {
      var zero = 160;
      var key = util.hexStringToBinaryArray("A7C083FEB7");
      var iv = util.hexStringToBinaryArray("00112233445566778899AABBCCDDEEFF");
      var pt = zeroedData(zero);
      var ct = util.hexStringToBinaryArray("FE81D2162C9A100D04895C454A77515BBE6A431A935CB90E2221EBB7EF502328943539492EFF6310C871054C2889CC728F82E86B1AFFF4334B6127A13A155C75151630BD482EB673FF5DB477FA6C53EBE1A4EC38C23C5400C315455D93A2ACED9598604727FA340D5F2A8BD757B77833F74BD2BC049313C80616B4A06268AE350DB92EEC4FA56C171374A67A80C006D0EAD048CE7B640F17D3D5A62D1F251C21");
            
      // Encrypt the data and verify
      var sosemanuk = new Sosemanuk(key, iv);
      var encrypted = sosemanuk.encrypt(pt);
      assert.deepEqual(ct, encrypted);

      // Encrypt the data and verify
      var sosemanuk = new Sosemanuk(key, iv);
      var decrypted = sosemanuk.decrypt(encrypted);            
      assert.deepEqual(zeroedData(zero), decrypted);
    }
      
    finished();
  },  
  
  
  // "Test Sosemanuk Vectors":function(assert, finished) {      
  //   // Test vectors
  //   for(var ij = 0; ij < testCases.length; ij++) {
  //     var zero = testCases[ij].zero;
  //     var key = util.hexStringToBinaryArray(testCases[ij].key);
  //     var iv = util.hexStringToBinaryArray(testCases[ij].iv);
  //     var stream = testCases[ij].stream;
  //     var xor = util.hexStringToBinaryArray(testCases[ij].xor);
  //     var pt = zeroedData(zero);
  //           
  //     // Encrypt the data and verify
  //     var sosemanuk = new Sosemanuk(key, iv);
  //     var encrypted = [];
  //     
  //     // Encrypt in chunks of data
  //     for(var j = 0, k = 0, l = 64, m = zero; k < m; j++) {
  //       l += j;
  //       if((k + l) > m) {
  //         l = m - k;
  //       }
  //       var crypted = sosemanuk.encrypt(pt.slice(k, k+l));
  //       encrypted = encrypted.concat(crypted);
  //       k += l;
  //     }
  //     
  //     // // Assert correctness of encryption
  //     // for(var i = 0; i < stream.length; i++) {
  //     //   var chunk = util.hexStringToBinaryArray(stream[i].chunk);
  //     //   var start = stream[i].start;
  //     //   var len = stream[i].len;
  //     //   assert.deepEqual(chunk, encrypted.slice(start, start + len));
  //     // }
  //     // 
  //     // // var bx = new Array(encrypted.length);
  //     // var out = new Array(xor.length);
  //     // for(var i = 0; i < xor.length; i++) out[i] = 0;
  //     // var bx = xorDigest(encrypted, out);
  //     // assert.deepEqual(xor, bx);
  //     // 
  //     // // Decrypt the data and verify
  //     // var sosemanuk = new Sosemanuk(key, iv);
  //     // var decrypted = [];
  //     // 
  //     // // Decrypt in chunks of data
  //     // for(var j = 0, k = 0, l = 64, m = zero; k < m; j++) {
  //     //   l += j;
  //     //   if((k + l) > m) {
  //     //     l = m - k;
  //     //   }
  //     //   var uncrypted = sosemanuk.decrypt(encrypted.slice(k, k+l));
  //     //   decrypted = decrypted.concat(uncrypted);
  //     //   k += l;
  //     // }
  //     // // Assert correct decryption
  //     // assert.deepEqual(pt, decrypted);
  //   }
  //     
  //   finished();
  // },  

  // "Streaming api test":function(assert, finished) {
  //   var key = "DC51C3AC3BFC62F12E3D36FE91281329";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 64;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var sosemanuk = new Sosemanuk(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += sosemanuk.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += sosemanuk.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += sosemanuk.finalEncrypt();    
  //   
  //   var sosemanuk = new Sosemanuk(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // One bang encryption
  //   var oneTimeEncryptedData = sosemanuk.encrypt(util.binaryStringToArray(data));
  //   // Ensure stream is compatible with the onetime encryption    
  //   assert.deepEqual(oneTimeEncryptedData, util.binaryStringToArray(encryptedData));
  //     
  //   // Convert onetime encrypted data to binary
  //   oneTimeEncryptedData = util.arrayToBinaryString(oneTimeEncryptedData);
  //     
  //   // Clean cbc instance
  //   sosemanuk = new Sosemanuk(util.hexStringToBinaryArray(key), util.hexStringToBinaryArray(iv));
  //   // Split the data
  //   var numberOfBlocks = Math.floor(oneTimeEncryptedData.length / blockSize);
  //   var leftOverbytes = oneTimeEncryptedData.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += sosemanuk.updateDecrypt(oneTimeEncryptedData.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += sosemanuk.updateDecrypt(oneTimeEncryptedData.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += sosemanuk.finalDecrypt();
  //     
  //   // Ensure stream is compatible with the onetime encryption    
  //   assert.deepEqual(util.binaryStringToArray(decryptedData), util.binaryStringToArray(data));
  //   finished();
  // },    
});

var testCases = [
  {
    zero:512,
    key:"80000000000000000000000000000000",
    iv:"0000000000000000",
    stream: [
      {
        start:0,
        len:64,
        chunk:"CF90FC5E0F232E6C74DCE3771E4CA9C2CAA7C6FBCAE6DCB60FE33F868B1A66A3B1A314BC3625BEFCD308195D12E717DA497936D25FC8DEFECA1B228E13D3ECAF"
      },    {
        start:192,
        len:64,
        chunk:"5C4B70D0BF8E5CF82DF5458E5B764B441C745CCF4A57B212B5BD90D4A85CF0FA7BBB62801BCA395DF91221893DF9DCD74CBC5044AB660549A981C9341DA161C6"
      },    {
        start:256,
        len:64,
        chunk:"FEF2AF8AE902C0D879A8BF82EA6D5FF687F52FCA782F426A1EE92E03D258C009C28B3ED831EE7557667506C9DDC4C9B45BCA9D77181CED4C987434DBD6249E93"
      },    {
        start:448,
        len:64,
        chunk:"ADDD772117157EC46AFAB14FBAAF60676A283A2B6837170AFC35BAE875DACD49D24B7DA7B7862AC403F4365B1AE1F7D9AE92349CB1ED5C903727F194D3C2239D"
      },
    ],
    xor:"E086EABA905815EF9598721DCD954B047098E4449FA1B072B1CE8C15891F4D931D4D8AA9732CB1B4521B2698B33FF6ABECD352769400E251F78A4525E6BB3BA5"
  },
];