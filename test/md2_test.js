require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  MD2 = require('hash/md2').MD2,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("MD2 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "MD2 test vectors":function(assert, finished) {
    var messages = [
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
    
    var digests = [
      "8350e5a3e24c153df2275c9f80692773",
      "32ec01ec4a6dac72c0ab96fb34c0b5d1",
      "da853b0d3f88d99b30283a69e6ded6bb",
      "ab4f496bfb2a530b219ff33031fe06b0",
      "4e8ddff3650292ab5a4108c3aa47940b",
      "da33def2a42df13975352846c30338cd",
      "d5976f79d83d3a0dc9806c3c66f3efd8" 
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var md2 = new MD2();
      md2.update(message);
      var result = md2.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 
  
  "MD2 node compatibility test":function(assert, finished) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("md2");
    var pureJsDigest = new MD2();
  
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
    assert.deepEqual(a, b)
    finished();
  } 
});

















