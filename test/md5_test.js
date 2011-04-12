require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  MD5 = require('hash/md5').MD5,
  crypto = require('crypto'),
  util = require('utils');
    
var suite = exports.suite = new TestSuite("MD5 Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "MD5 test vectors":function(assert, finished) {
    var messages = ["",
      "a",
      "abc",
      "abcdefghijklmnopqrstuvwxyz"
    ]
    
    var digests = ["d41d8cd98f00b204e9800998ecf8427e",
      "0cc175b9c0f1b6a831c399e269772661",
      "900150983cd24fb0d6963f7d28e17f72",
      "c3fcd3d76192e4007dfb496cca67e13b"
    ]
    
    for(var i = 0; i < messages.length; i++) {
      var message = messages[i];
      var digest = util.hexStringToBinaryArray(digests[i]);
      
      var md5 = new MD5();
      md5.update(message);
      var result = md5.digest('array');
      assert.deepEqual(digest, result);
    }
    
    finished();
  },  
});

















