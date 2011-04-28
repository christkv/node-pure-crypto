require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  GOST3411 = require('hash/gost3411').GOST3411,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("GOST3411 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "GOST3411 test vectors":function(assert, finished) {
    var messages = [
      "",
      "This is message, length=32 bytes",
      "Suppose the original message has length = 50 bytes",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    ]
    
    var digests = [
      "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0",
      "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
      "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
      "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var gost3411 = new GOST3411();
      gost3411.update(message);
      var result = gost3411.digest('array');
      // debug("----------------------------------------------------------- result")
      // debug(result)
      // debug("----------------------------------------------------------- digest")
      // debug(digest)      
      assert.deepEqual(digest, result);
    }
    
    finished();
  }, 

  "GOST3411 million a vector":function(assert, finished) {
    var digest = util.hexStringToBinaryArray("8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f");
    var numberOfAs = 1000000;
    var gost3411 = new GOST3411();
    
    for(var i = 0; i < numberOfAs; i++) {
      gost3411.update('a');
    }
  
    var result = gost3411.digest('array');
    assert.deepEqual(digest, result);
    finished();
  },   
});

















