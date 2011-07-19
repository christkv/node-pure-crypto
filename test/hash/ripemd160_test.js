require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  RIPEMD160 = require('hash/ripemd160').RIPEMD160,
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

  "RIPEMD160 test vectors":function(test) {
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
      "9c1185a5c5e9fc54612808977ee8f548b2258d31",
      "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
      "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
      "5d0689ef49d2fae572b881b123a85ffa21595f36",
      "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
      "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
      "b0e20b6e3116640286ed3a87a5713079b21f5189",
      "9b752e45573d4b39f4dbd3323cab82bf63326bfb"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var hash = new RIPEMD160();
      hash.update(message);
      var finalDigest = new Array(hash.getDigestSize());
      test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
      test.deepEqual(digest, finalDigest);
    }
    
    test.done();
  }, 
  
  "RIPEMD160 million a vector":function(test) {
    var digest = util.hexStringToBinaryArray("52783243c1697bdbe16d37f97f68f08325dc1528");
    var numberOfAs = 1000000;
    var hash = new RIPEMD160();
    
    for(var i = 0; i < numberOfAs; i++) {
      hash.update('a');
    }
  
    var finalDigest = new Array(hash.getDigestSize());
    test.equal(hash.getDigestSize(), hash.doFinal(finalDigest, 0));
    test.deepEqual(digest, finalDigest);
    test.done();
  },   
  
  // "RIPEMD160 node compatibility test":function(test) {
  //   var data = randomdata(1025);
  //   var nodeDigest = crypto.createHash("rmd160");
  //   var pureJsDigest = new RIPEMD160();
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

















