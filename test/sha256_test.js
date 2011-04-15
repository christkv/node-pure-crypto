require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  SHA256 = require('hash/sha256').SHA256,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("SHA256 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "SHA256 test vectors":function(assert, finished) {
    var messages = [
      "",
      "a",
      "abc",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    ]
    
    var digests = [
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var sha256 = new SHA256();
      sha256.update(message);
      var result = sha256.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 

  "SHA256 million a vector":function(assert, finished) {
    var digest = util.hexStringToBinaryArray("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    var numberOfAs = 1000000;
    var sha256 = new SHA256();
    
    for(var i = 0; i < numberOfAs; i++) {
      sha256.update('a');
    }
  
    var result = sha256.digest('array');
    assert.deepEqual(digest, result);
    
    finished();
  }, 
  
  "SHA256 node compatibility test":function(assert, finished) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("sha256");
    var pureJsDigest = new SHA256();
  
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

















