require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  // CFBBlockCipherMac = require('mac/hmac').CFBBlockCipherMac,
  crypto = require('crypto'),
  DESKey = require('symmetric/block/des').DESKey,
  CFBBlockCipherMac = require('mac/cfbblockciphermac').CFBBlockCipherMac,
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

  "CFBBlockCipherMac test vectors":function(test) {
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

      var cipher = new DESKey();
      var blockCipher = new CFBBlockCipherMac(cipher, iv);
      blockCipher.init(key);
      blockCipher.update(message);
      var digest = blockCipher.digest('array');
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 
});
