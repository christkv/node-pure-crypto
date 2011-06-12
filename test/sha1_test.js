require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  SHA1 = require('hash/sha1').SHA1,
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

  "SHA1 test vectors":function(test) {
    var messages = [
      "",
      "a",
      "abc",
      "abcdefghijklmnopqrstuvwxyz"
    ]
    
    var digests = [
      "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
      "a9993e364706816aba3e25717850c26c9cd0d89d",
      "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var sha1 = new SHA1();
      sha1.update(message);
      var result = sha1.digest('array');
      test.deepEqual(digest, result);
    }
    
    test.done();
  }, 
  
  "SHA1 node compatibility test":function(test) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("sha1");
    var pureJsDigest = new SHA1();
  
    // Size of blocs
    var blockSize = 64;
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
  
    // Split and hash
    for(var i = 0; i < numberOfBlocks; i++) {
      var split = data.slice(i * blockSize, (i * blockSize) + blockSize);
      // Update digest
      nodeDigest.update(split);
      pureJsDigest.update(split);
    }
    
    var a = util.binaryStringToArray(nodeDigest.digest());
    var b = util.binaryStringToArray(pureJsDigest.digest());    
    test.deepEqual(a, b)
    test.done();
  } 
});

















