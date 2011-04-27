require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  MD4 = require('hash/md4').MD4,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("MD4 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "MD4 test vectors":function(assert, finished) {
    var messages = [
      "",
      "a",
      "abc",
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    ]
    
    var digests = [
      "31d6cfe0d16ae931b73c59d7e0c089c0",
      "bde52cb31de33e46245e05fbdbd6fb24",
      "a448017aaf21d8525fc10ae87aa6729d",
      "e33b4ddc9c38f2199c3e7b164fcc0536"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var md4 = new MD4();
      md4.update(message);
      var result = md4.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 
  
  "MD4 node compatibility test":function(assert, finished) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("md4");
    var pureJsDigest = new MD4();
  
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
















