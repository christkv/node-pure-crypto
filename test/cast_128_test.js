require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  CAST128 = require('cast_128').CAST128,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("CAST-128 tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test CAST-128 Vectors":function(assert, finished) {
    var keys = ["0123456712", "01234567123456782345", "0123456712345678234567893456789A"];
    var pts = ["0123456789ABCDEF", "0123456789ABCDEF", "0123456789ABCDEF"];
    var cts = ["7AC816D16E9B302E", "EB6A711A2C02271B", "238B4FE5847E44B2"];
    
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      
      // Encrypt the data and verify
      var cast128 = new CAST128(key);
      var encrypted = cast128.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      cast128 = new CAST128(key);
      var decrypted = cast128.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },  
});