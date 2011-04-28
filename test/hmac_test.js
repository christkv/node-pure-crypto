require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  crypto = require('crypto'),
  HMac = require('mac/hmac').HMac,
  MD5 = require('hash/md5').MD5,
  util = require('utils');
    
var suite = exports.suite = new TestSuite("HMac Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "HMac MD5 test vectors":function(assert, finished) {
    var keys = [
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      "4a656665",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ];
    
    var messages = [
      "Hi There",
      "what do ya want for nothing?",
      "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "Test With Truncation",
      "Test Using Larger Than Block-Size Key - Hash Key First",
      "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    ];

    var digests = [
      "9294727a3638bb1c13f48ef8158bfc9d",
      "750c783e6ab0b503eaa86e310a5db738",
      "56be34521d144c88dbb8c733f0e8b3f6",
      "697eaf0aca3a3aea3a75164746ffaa79",
      "56461ef2342edc00f9bab995690efd4c",
      "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
      "6f630fad67cda0ee1fb1f562db3aa53e"
    ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var message = util.binaryStringToArray(messages[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);

      var hmac = new HMac(new MD5(), key);
      hmac.update(message);
      var output = hmac.digest('array');
      // assert.deepEqual(output, digest);          
    }
    
    finished();
  }, 
});
