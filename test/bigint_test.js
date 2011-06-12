
var testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug,
  inspect = require('util').inspect,
  BigInteger = require('../lib/big_integer').BigInteger;
    
module.exports = testCase({
  setUp: function(callback) {
    callback();
  },
  
  tearDown: function(callback) {
    callback();        
  },

  'Should correctly create new big integers and perform additions' : function(test) {
		var n1 = BigInteger.nbv(25);
		var n2 = BigInteger.nbv(1002);
		var n3 = n1.add(n2);
		var v = n3.valueOf();
    test.equal("1027", v.toString());
    
		var p = new BigInteger("e564d8b801a61f47", 16, true);
		var xp = new BigInteger("99246db2a3507fa", 16, true);		
		xp = xp.add(p);
		
		test.equal("eef71f932bdb2741", xp.toString(16));
    test.done();
  },
  
  'Should correctly handle signed big intgers after subtraction' : function(test) {
    var i1 = new BigInteger("1");
    var i2 = new BigInteger("2");
    var i3 = i1.subtract(i2);
    var arr_i3 = i3.toByteArray(); // FF
    var i4 = new BigInteger(arr_i3);
    var arr_i4 = i4.toByteArray(); // FF
    var equal = i3.equals(i4);    
    
    test.equal(1, arr_i3.length);
    test.equal(1, arr_i4.length);
    test.equal(true, i3.equals(i4));    
    test.done();
  },
  
  'Should correctly create new singed big integer' : function(test) {
		var i1 = BigInteger.nbv(-13);
    test.equal(-13, i1.valueOf());
    test.done();
  }
});










