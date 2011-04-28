require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  crypto = require('crypto'),
  DESKey = require('block/des').DESKey,
  PKCS7 = require('prng/pkcs7').PKCS7,
  CBCBlockCipherMac = require('mac/cbcblockciphermac').CBCBlockCipherMac,
  util = require('utils');
    
var suite = exports.suite = new TestSuite("CBCBlockCipherMac Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "CBCBlockCipherMac test vectors":function(assert, finished) {
    var keys = ["0123456789abcdef", "0123456789abcdef"];
    var ivs = [null, util.hexStringToBinaryArray("1234567890abcdef")];
    var messages = ["37363534333231204e6f77206973207468652074696d6520666f7220",
      "37363534333231204e6f77206973207468652074696d6520666f7220"];
    var outputs = ["f1d30f68", "58d2e77e"];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var iv = ivs[i];
      var message = util.hexStringToBinaryArray(messages[i]);
      var output = util.hexStringToBinaryArray(outputs[i]);

      var cipher = new DESKey(key);
      var blockCipher = new CBCBlockCipherMac(cipher, iv);
      blockCipher.update(message);
      var digest = blockCipher.digest('array');
      assert.deepEqual(output, digest);          
    }
    
    finished();
  }, 

  "CBCBlockCipherMac padding test vectors":function(assert, finished) {
    var keys = ["0123456789abcdef", "0123456789abcdef"];
    var ivs = [null, null];
    var messages = ["3736353433323120",
      "37363534333231204e6f77206973207468652074696d6520666f7220"];
    var outputs = ["188fbdd5", "7045eecd"];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var iv = ivs[i];
      var message = util.hexStringToBinaryArray(messages[i]);
      var output = util.hexStringToBinaryArray(outputs[i]);

      var cipher = new DESKey(key);
      var blockCipher = new CBCBlockCipherMac(cipher, iv, null, new PKCS7());
      blockCipher.update(message);
      var digest = blockCipher.digest('array');
      assert.deepEqual(output, digest);          
    }
    
    finished();
  }, 
});
