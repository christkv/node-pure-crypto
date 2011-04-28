require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  // HMac = require('mac/hmac').HMac,
  crypto = require('crypto'),
  DESKey = require('block/des').DESKey,
  CBCBlockCipherMac = require('mac/cbcblockciphermac').CBCBlockCipherMac,
  util = require('utils');
    
var suite = exports.suite = new TestSuite("HMac Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "HMac test vectors":function(assert, finished) {
    var key = util.hexStringToBinaryArray("0123456789abcdef");
    var message = util.hexStringToBinaryArray("37363534333231204e6f77206973207468652074696d6520666f7220");
    var output = util.hexStringToBinaryArray("f1d30f68");

    var cipher = new DESKey(key);
    var blockCipher = new CBCBlockCipherMac(cipher);
    blockCipher.update(message);
    var digest = blockCipher.digest('array');
    assert.deepEqual(output, digest);    
    finished();
  }, 

  // "HMac test vectors":function(assert, finished) {
  //   var vectors = parseMac(macString);
  //   
  //   for(var i = 0; i < vectors.length; i++) {
  //     var vector = vectors[i];
  //     
  //     // Unpack test vector
  //     var stateSize = vector.stateSize;
  //     var hashBitLength = vector.hashBitLength;
  //     var msgLength = vector.msgLength;
  //     var message = vector.message.length >= 2 ? util.hexStringToBinaryArray(vector.message) : [];
  //     var mac = util.hexStringToBinaryArray(vector.mac);
  //     var digest = util.hexStringToBinaryArray(vector.result);
  //       
  //     if(vector.mac.match(/\(none\)/) == null) {
  //       var hmac = new HMac(stateSize, hashBitLength, mac);
  //       hmac.updateBits(message, msgLength);
  //       var result = hmac.digest('array');
  //       assert.deepEqual(digest, result);      
  //     }
  //   }
  //   
  //   finished();
  // }  
});
