require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  RIPEMD128 = require('hash/ripemd128').RIPEMD128,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("RIPEMD128 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "RIPEMD128 test vectors":function(assert, finished) {
    var messages = [
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
    
    var digests = [
      "cdf26213a150dc3ecb610f18f6b38b46",
      "86be7afa339d0fc7cfc785e72f578d33",
      "c14a12199c66e4ba84636b0f69144c77",
      "9e327b3d6e523062afc1132d7df9d1b8",
      "fd2aa607f71dc8f510714922b371834e",
      "a1aa0689d0fafa2ddc22e88b49133a06",
      "d1e959eb179c911faea4624c60c5c702",
      "3f45ef194732c2dbb2c4a2c769795fa3"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var ripemd128 = new RIPEMD128();
      ripemd128.update(message);
      var result = ripemd128.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 
  
  "RIPEMD128 million a vector":function(assert, finished) {
    var digest = util.hexStringToBinaryArray("4a7f5723f954eba1216c9d8f6320431f");
    var numberOfAs = 1000000;
    var ripemd128 = new RIPEMD128();
    
    for(var i = 0; i < numberOfAs; i++) {
      ripemd128.update('a');
    }
  
    var result = ripemd128.digest('array');
    assert.deepEqual(digest, result);
    
    finished();
  },   
  
  // "RIPEMD128 node compatibility test":function(assert, finished) {
  //   var data = randomdata(1025);
  //   var nodeDigest = crypto.createHash("rmd160");
  //   var pureJsDigest = new RIPEMD128();
  // 
  //   // Size of blocs
  //   var blockSize = 64;
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  // 
  //   // Split and hash
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     var split = data.slice(i * blockSize, (i * blockSize) + blockSize);
  //     // Update digest
  //     nodeDigest.update(split);
  //     pureJsDigest.update(split);
  //   }
  //   
  //   var a = util.binaryStringToArray(nodeDigest.digest());
  //   var b = util.binaryStringToArray(pureJsDigest.digest());    
  //   assert.deepEqual(a, b)
  //   finished();
  // } 
});

















