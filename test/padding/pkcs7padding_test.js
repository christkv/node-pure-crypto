require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  crypto = require('crypto'),
  PKCS7Padding = require('padding/pkcs7padding').PKCS7Padding,
  PaddedBufferedBlockCipher = require('symmetric/paddedbufferedblockcipher').PaddedBufferedBlockCipher,
  DES = require('symmetric/block/des').DES,
  Random = require('prng/random').Random,
  util = require('utils');
    
var zeroedArray = function(size) {
  var a = new Buffer(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "PKCS7Padding test vectors":function(test) {
    var ffVector = util.hexStringToBinaryArray("ffffff0505050505");
    var zeroVector = util.hexStringToBinaryArray("0000000004040404");
    var data = [0xff, 0xff, 0xff, 0, 0, 0, 0, 0];
    var key = util.hexStringToBinaryArray("0011223344556677");

    // var random = new Random();
    var padding = new PKCS7Padding();
    padding.init();
    var cipher = new PaddedBufferedBlockCipher(new DES(), padding);
    var random = new Random();
    random.seed();
    
    // ff test
    padding.addPadding(data, 3);
    test.deepEqual(ffVector, data);
    
    // zero test
    data = zeroedArray(8);
    padding.addPadding(data, 4);
    test.deepEqual(zeroVector, data);
    
    data = zeroedArray(8);
    try {
      padding.padCount(data);
      test.fail("Failed due to error not thrown", "", "")
    } catch (err) {}    
    
    for(var i = 1; i != 200; i++) {
      data = zeroedArray(i);
      random.nextBytes(data);    
      blockCheck(test, cipher, padding, key, data);
    }
    
    test.done();
  }, 
});

var blockCheck = function(test, cipher, padding, key, data) {
  var out = zeroedArray(data.length + 8);
  var dec = zeroedArray(data.length);
  
  try {
    cipher.init(true, key);
    var len = cipher.processBytes(data, 0, data.length, out, 0);
    len += cipher.doFinal(out, len);

    cipher.init(false, key);
    var decLen = cipher.processBytes(out, 0, len, dec, 0);
    decLen += cipher.doFinal(dec, decLen);    
    test.deepEqual(data, dec);    
  } catch(err) {
    test.fail("Should not fail with exception: " + inspect(err));
  }
}

