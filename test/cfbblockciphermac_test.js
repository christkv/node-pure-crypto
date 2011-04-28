require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  // CFBBlockCipherMac = require('mac/hmac').CFBBlockCipherMac,
  crypto = require('crypto'),
  DESKey = require('block/des').DESKey,
  CFBBlockCipherMac = require('mac/cfbblockciphermac').CFBBlockCipherMac,
  util = require('utils');
    
var suite = exports.suite = new TestSuite("CFBBlockCipherMac Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "CFBBlockCipherMac test vectors":function(assert, finished) {
    var keys = ["0123456789abcdef", "0123456789abcdef"];
    var ivs = [util.hexStringToBinaryArray("1234567890abcdef"),
      util.hexStringToBinaryArray("1234567890abcdef")];
    var messages = ["37363534333231204e6f77206973207468652074696d6520666f7220",
      "3736353433323120"];
    var outputs = ["cd647403",
      "3af549c9"];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var iv = ivs[i];
      var message = util.hexStringToBinaryArray(messages[i]);
      var output = util.hexStringToBinaryArray(outputs[i]);

      var cipher = new DESKey(key);
      var blockCipher = new CFBBlockCipherMac(cipher, iv);
      blockCipher.update(message);
      var digest = blockCipher.digest('array');
      assert.deepEqual(output, digest);          
    }
    
    finished();
  }, 
});
