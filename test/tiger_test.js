require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  Tiger = require('hash/tiger').Tiger,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("Tiger Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Tiger test vectors":function(assert, finished) {
    var messages = [
      "",
      "abc",
      "Tiger",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvw",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
      "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
    ]
    
    var digests = [
      "3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3",
      "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93",
      "DD00230799F5009FEC6DEBC838BB6A27DF2B9D6F110C7937",
      "F71C8583902AFB879EDFE610F82C0D4786A3A534504486B5",
      "38F41D9D9A710A10C3727AC0DEEAA270727D9F926EC10139",
      "48CEEB6308B87D46E95D656112CDF18D97915F9765658957",
      "631ABDD103EB9A3D245B6DFD4D77B257FC7439501D1568DD",
      "C54034E5B43EB8005848A7E0AE6AAC76E4FF590AE715FD25",
      "C54034E5B43EB8005848A7E0AE6AAC76E4FF590AE715FD25"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var tiger = new Tiger();
      tiger.update(message);
      var result = tiger.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 
  
  "Tiger 64K vector":function(assert, finished) {
    var digest = util.hexStringToBinaryArray("FDF4F5B35139F48E710E421BE5AF411DE1A8AAC333F26204");
    var numberOfAs = 65536;
    var tiger = new Tiger();
    
    for(var i = 0; i < numberOfAs; i++) {
      tiger.update([i & 0xff]);
    }
  
    var result = tiger.digest('array');
    assert.deepEqual(digest, result);
    
    finished();
  },   
});

















