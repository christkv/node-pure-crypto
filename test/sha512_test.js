require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  SHA512 = require('hash/sha512').SHA512,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("SHA512 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "SHA512 test vectors":function(assert, finished) {
    var messages = [
      "",
      "a",
      "abc",
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    ]
    
    var digests = [
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"   
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var sha512 = new SHA512();
      sha512.update(message);
      var result = sha512.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 

  "SHA512 million a vector":function(assert, finished) {
    var digest = util.hexStringToBinaryArray("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    var numberOfAs = 1000000;
    var sha512 = new SHA512();
    
    for(var i = 0; i < numberOfAs; i++) {
      sha512.update('a');
    }
  
    var result = sha512.digest('array');
    assert.deepEqual(digest, result);
    
    finished();
  }, 
  
  "SHA512 node compatibility test":function(assert, finished) {
    var data = randomdata(1025);
    var nodeDigest = crypto.createHash("sha512");
    var pureJsDigest = new SHA512();
  
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

















