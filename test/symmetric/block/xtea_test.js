require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  XTea = require('symmetric/block/xtea').XTea,
  util = require('utils'),
  crypto = require('crypto');

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }

  return array;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },

  tearDown: function(callback) {
    callback();        
  },

  "Test MARC4 Vectors":function(test) {
    var keys = ["00000000000000000000000000000000", "00000000000000000000000000000000", "0123456712345678234567893456789A",
          "0123456712345678234567893456789A"];
    var pts =["0000000000000000", "0102030405060708", "0000000000000000",
          "0102030405060708"];
    var cts = ["dee9d4d8f7131ed9", "065c1b8975c6a816", "1ff9a0261ac64264",
          "8c67155b2ef91ead"];

    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);

      // Encrypt data
      var cipher = new XTea();
      cipher.init(true, key);
      test.equal(8, cipher.processBlock(data, 0, data, 0));  // Destructive to save memory      
      test.deepEqual(ct, data);

      // Initialize cipher for decryption
      cipher.init(false, key);
      // Decrypt the encrypted data and compare
      test.equal(8, cipher.processBlock(data, 0, data, 0));
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }

    test.done();
  },
});















