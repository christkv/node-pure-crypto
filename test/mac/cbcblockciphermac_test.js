require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  crypto = require('crypto'),
  DES = require('symmetric/block/des').DES,
  PKCS7 = require('prng/pkcs7').PKCS7,
  CBCBlockCipherMac = require('mac/cbcblockciphermac').CBCBlockCipherMac,
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

  "CBCBlockCipherMac test vectors":function(test) {
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

      var cipher = new DES();
      var blockCipher = new CBCBlockCipherMac(cipher);
      blockCipher.init(iv, key);
      blockCipher.update(message);
      var out = new Array(4);
      blockCipher.doFinal(out, 0);
      test.deepEqual(output, out);
    }
    
    test.done();
  }, 

  "CBCBlockCipherMac padding test vectors":function(test) {
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
  
      var cipher = new DES();
      var blockCipher = new CBCBlockCipherMac(cipher, null, new PKCS7());
      blockCipher.init(iv, key);
      blockCipher.update(message);
      var out = new Array(4);
      blockCipher.doFinal(out, 0);
      test.deepEqual(output, out);
    }
    
    test.done();
  }, 
});
