require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  MD5 = require('hash/md5').MD5,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("MD5 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "MD5 test vectors":function(assert, finished) {
    var messages = ["",
      "a",
      "abc",
      "abcdefghijklmnopqrstuvwxyz"
    ]
    
    var digests = ["d41d8cd98f00b204e9800998ecf8427e",
      "0cc175b9c0f1b6a831c399e269772661",
      "900150983cd24fb0d6963f7d28e17f72",
      "c3fcd3d76192e4007dfb496cca67e13b"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var md5 = new MD5();
      md5.update(message);
      var result = md5.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 
  
  "MD5 node compatibility test":function(assert, finished) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("md5");
    var pureJsDigest = new MD5();

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

















