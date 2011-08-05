require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  crypto = require('crypto'),
  HMac = require('mac/hmac').HMac,
  MD5 = require('hash/md5').MD5,
  SHA1 = require('hash/sha1').SHA1,
  SHA224 = require('hash/sha224').SHA224,
  SHA256 = require('hash/sha256').SHA256,
  SHA384 = require('hash/sha384').SHA384,
  SHA512 = require('hash/sha512').SHA512,
  RIPEMD128 = require('hash/ripemd128').RIPEMD128,
  RIPEMD160 = require('hash/ripemd160').RIPEMD160,
  RIPEMD256 = require('hash/ripemd256').RIPEMD256,
  RIPEMD320 = require('hash/ripemd320').RIPEMD320,
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "HMac MD5 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    ];

    var digests = [
      "9294727a3638bb1c13f48ef8158bfc9d",
      "750c783e6ab0b503eaa86e310a5db738",
      "56be34521d144c88dbb8c733f0e8b3f6",
      "697eaf0aca3a3aea3a75164746ffaa79",
      "56461ef2342edc00f9bab995690efd4c",
      "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
      "6f630fad67cda0ee1fb1f562db3aa53e"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);

      var hmac = new HMac(new MD5());
      hmac.init(key);
      // Update
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 

  "HMac SHA1 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    ];
  
    var digests = [
      "b617318655057264e28bc0b6fb378c8ef146be00",
      "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
      "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
      "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
      "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
      "aa4ae5e15272d00e95705637ce8a3b55ed402112",
      "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
      "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
      "aa4ae5e15272d00e95705637ce8a3b55ed402112",
      "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new SHA1());
      hmac.init(key);      
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac SHA224 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    ];
  
    var digests = [
      "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
      "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
      "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
      "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
      "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c",
      "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
      "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new SHA224());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac SHA256 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    ];
  
    var digests = [
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
      "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new SHA256());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac SHA384 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    ];
  
    var digests = [
      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
      "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
      "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
      "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
      "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea",
      "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
      "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new SHA384());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac SHA512 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    ];
  
    var digests = [
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
      "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
      "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
      "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
      "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
      "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new SHA512());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac RIPEMD128 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    ];
  
    var digests = [
      "fbf61f9492aa4bbf81c172e84e0734db",
      "875f828862b6b334b427c55f9f7ff09b",
      "09f0b2846d2f543da363cbec8d62a38d",
      "bdbbd7cf03e44b5aa60af815be4d2294",
      "e79808f24b25fd031c155f0d551d9a3a",
      "dc732928de98104a1f59d373c150acbb",
      "5c6bec96793e16d40690c237635f30c5"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new RIPEMD128());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
  
  "HMac RIPEMD160 test vectors":function(test) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    ];
  
    var digests = [
      "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
      "dda6c0213a485a9e24f4742064a7f033b43c4069",
      "b0b105360de759960ab4f35298e116e295d8e7c1",
      "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
      "7619693978f91d90539ae786500ff3d8e0518e39",
      "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
      "69ea60798d71616cce5fd0871e23754cd75d5a0a"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = messages[i];
      message = message.substr(0, 2) == "0x" ?  util.hexStringToBinaryArray(message.substr(2)) : util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
  
      var hmac = new HMac(new RIPEMD160());
      hmac.init(key);
      hmac.update(message);
      // Allocate output size for mac
      var output = new Array(hmac.getMacSize());
      // Calculare final mac
      hmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
});
