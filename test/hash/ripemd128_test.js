require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  RIPEMD128 = require('hash/ripemd128').RIPEMD128,
  crypto = require('crypto'),
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

  "RIPEMD128 test vectors":function(test) {
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
      
      var hash = new RIPEMD128();
      hash.update(message);
      var finalDigest = new Array(hash.getDigestSize());
      test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
      test.deepEqual(digest, finalDigest);
    }
    
    test.done();
  }, 
  
  "RIPEMD128 million a vector":function(test) {
    var digest = util.hexStringToBinaryArray("4a7f5723f954eba1216c9d8f6320431f");
    var numberOfAs = 1000000;
    var hash = new RIPEMD128();
    
    for(var i = 0; i < numberOfAs; i++) {
      hash.update('a');
    }
  
    var finalDigest = new Array(hash.getDigestSize());
    test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
    test.deepEqual(digest, finalDigest);
    test.done();
  },   
});

















