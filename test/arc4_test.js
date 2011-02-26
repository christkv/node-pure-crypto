require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  ARC4 = require('arc4').ARC4,
  util = require('utils'),
  crypto = require('crypto');
  
var suite = exports.suite = new TestSuite("ARC4 tests");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Test ARC4 Vectors":function(assert, finished) {
    var keys = ["0123456789ABCDEF", "618A63D2FB"];
    var pts = ["0000000000000000", "DCEE4CF92C"];
    var cts = ["7494C2E7104B0879", "F13829C9DE"];
    var drops = [0, 0];    
  
    // Test vectors
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var drop = drops[i];
      
      // Encrypt the data and verify
      var arc4 = new ARC4(key);
      var encrypted = arc4.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      
      // Decrypt data and verify
      arc4 = new ARC4(key);
      var decrypted = arc4.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
      
    finished();
  },
  
  "More Arc4 tests - Arc4 is MARC 4 with drop = 0":function(assert, finished) {
    var key = "Key";
    var pt = "Plaintext";

    var arc4 = new ARC4(util.binaryStringToArray(key));
    var src = arc4.encrypt(util.binaryStringToArray(pt));
    assert.deepEqual(util.hexStringToBinaryArray("BBF316E8D940AF0AD3"), src)

    var key = "Wiki";
    var pt = "pedia";

    var arc4 = new ARC4(util.binaryStringToArray(key));
    var src = arc4.encrypt(util.binaryStringToArray(pt));
    assert.deepEqual(util.hexStringToBinaryArray("1021BF0420"), src)

    var key = "Secret";
    var pt = "Attack at dawn";

    var arc4 = new ARC4(util.binaryStringToArray(key));
    var src = arc4.encrypt(util.binaryStringToArray(pt));
    assert.deepEqual(util.hexStringToBinaryArray("45A01F645FC35B383552544B9BF5"), src)

    finished();
  },  
});