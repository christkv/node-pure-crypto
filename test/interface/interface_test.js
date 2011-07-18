require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  crypto = require('crypto'),
  util = require('utils'),
  path = require('path'),
  fs = require('fs');

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Verify all block ciphers follow expected interface standard":function(test) {
    var filePath = "./lib/symmetric/block";
    // Read all the block cipher names
    var files = fs.readdirSync(filePath)
    // Iterate over each file
    for(var i = 0; i < files.length; i++) {
      var stat = fs.statSync(filePath + "/" + files[i]);
      if(stat.isFile() && path.extname(files[i]) == '.js') {
        var module = require(filePath.replace('./', '') + "/" + files[i]);
        
        // Check that we have only one key in the module
        test.equal(1, Object.keys(module).length);
        // Extract class for key
        var classDefinition = module[Object.keys(module)[0]];
        // Initialize a object
        var object = new classDefinition;
        
        console.log("  = " + files[i])
        // Assert method existence
        // debug(inspect(// object['getAlgorithmName']))
        test.ok(typeof object['getAlgorithmName'] == 'function');
        test.ok(typeof object['getBlockSize'] == 'function');
        test.ok(typeof object['reset'] == 'function');
        test.ok(typeof object['processBlock'] == 'function');
        test.ok(typeof object['init'] == 'function');        
      }
    }
    
    test.done();
  },  
});


















