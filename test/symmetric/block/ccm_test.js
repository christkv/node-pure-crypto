require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  AES = require('symmetric/block/aes').AES,
  XTea = require('symmetric/block/xtea').XTea,
  CCM = require('symmetric/block/ccm').CCM,
  NullPad = require('symmetric/padding/null').NullPad,
  crypto = require('crypto'),
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

var zeroedData = function(size) {
  var data = new Array(size);
  for(var i = 0; i < size; i++) data[i] = 0;
  return data;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test CCM Vectors":function(test) {
    var keys = ["404142434445464748494a4b4c4d4e4f", "404142434445464748494a4b4c4d4e4f", "404142434445464748494a4b4c4d4e4f", "404142434445464748494a4b4c4d4e4f"];
    var nonces = ["10111213141516", "1011121314151617", "101112131415161718191a1b", "101112131415161718191a1b1c"];
    var additionalTexts = ["0001020304050607", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f10111213", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"];
    var pts = ["20212223", "202122232425262728292a2b2c2d2e2f", "202122232425262728292a2b2c2d2e2f3031323334353637", "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"];
    var cts = ["7162015b4dac255d", "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd", "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951", "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b"];
    var macs = ["6084341b", "7f479ffca464", "67c99240c7d51048", "f4dd5d0ee404617225ffe34fce91"];
    var macSizes = [32, 48, 64];
    
    // Process all the keys
    for(var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var nonce = nonces[i];
      var additionalText = additionalTexts[i];
      var pt = pts[i];
      var ct = cts[i];
      var mac = macs[i];
      
      // Test different mac sizes
      for(var j = 0; j < macSizes.length; j++) {        
        var macSize = macSizes[j];
        // CCM initalize
        var ccm = new CCM(new AES());
        ccm.init(true, false, key, macSize, nonce, additionalText);
        
      }
    }

    test.ok(false);

    test.done();
  },  
});


















