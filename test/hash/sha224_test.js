require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  SHA224 = require('hash/sha224').SHA224,
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

  "SHA224 test vectors":function(test) {
    var messages = [
      "",
      "a",
      "abc",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    ]
    
    var digests = [
      "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
      "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
      "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var hash = new SHA224();
      hash.update(message);
      var finalDigest = new Array(hash.getDigestSize());
      test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
      test.deepEqual(digest, finalDigest);
    }
    
    test.done();
  }, 

  "SHA224 million a vector":function(test) {
    var digest = util.hexStringToBinaryArray("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67");
    var numberOfAs = 1000000;
    var hash = new SHA224();
    
    for(var i = 0; i < numberOfAs; i++) {
      hash.update('a');
    }
  
    var finalDigest = new Array(hash.getDigestSize());
    test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
    test.deepEqual(digest, finalDigest);
    test.done();
  }, 
  
  // "SHA224 node compatibility test":function(test) {
  //   var data = randomdata(1025);
  //   var nodeDigest = crypto.createHash("sha224");
  //   var pureJsDigest = new SHA224();
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
  //   test.deepEqual(a, b)
  //   test.done();
  // } 
});

















