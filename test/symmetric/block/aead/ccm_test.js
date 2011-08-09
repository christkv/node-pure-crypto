require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../../deps/nodeunit'),
  AES = require('symmetric/block/aes').AES,
  XTea = require('symmetric/block/xtea').XTea,
  CCM = require('symmetric/block/aead/ccm').CCM,
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

var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
}

var binaryStringToArray = exports.binaryStringToArray = function(string) {
  var array = [];
  
  for (var i = 0; i < string.length; i++) {
    if (string.charCodeAt(i)<32) {array.push(string.charCodeAt(i) & 0xff);}
    else {array.push(string.charCodeAt(i) & 0xff)}    
  }  
  return array;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Test CCM Vectors":function(test) {
    var keys = ["404142434445464748494a4b4c4d4e4f", "404142434445464748494a4b4c4d4e4f", "404142434445464748494a4b4c4d4e4f"];
    var nonces = ["10111213141516", "1011121314151617", "101112131415161718191a1b"];
    var additionalTexts = ["0001020304050607", "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f10111213"];
    var pts = ["20212223", "202122232425262728292a2b2c2d2e2f", "202122232425262728292a2b2c2d2e2f3031323334353637"];
    var cts = ["7162015b4dac255d", "d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd", "e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951"];
    var macs = ["6084341b", "7f479ffca464", "67c99240c7d51048"];
    var macSizes = [32, 48, 64];
    
    // Process all the keys
    for(var i = 0; i < keys.length; i++) {
      var key = hexStringToBinaryArray(keys[i]);
      var nonce = hexStringToBinaryArray(nonces[i]);
      var additionalText = hexStringToBinaryArray(additionalTexts[i]);
      var pt = hexStringToBinaryArray(pts[i]);
      var ct = hexStringToBinaryArray(cts[i]);
      var mac = hexStringToBinaryArray(macs[i]);      
      var macSize = macSizes[i];
  
      // CCM initalize
      var ccm = new CCM(new AES());
      ccm.init(true, false, key, macSize, nonce, additionalText);
      
      // Set up tmp
      var enc = new Array(ct.length)
      // Process the data
      var len = ccm.processBytes(pt, 0, pt.length, enc, 0);  // Destructive to save memory      
      len += ccm.doFinal(enc, len);
      // var output = new Array()
      test.equal(ct.length, len);
      test.deepEqual(ct, enc);              
      
      // Decrypt
      // CCM initalize
      var key = hexStringToBinaryArray(keys[i]);
      var nonce = hexStringToBinaryArray(nonces[i]);
      var additionalText = hexStringToBinaryArray(additionalTexts[i]);
      var pt = hexStringToBinaryArray(pts[i]);
      var ct = hexStringToBinaryArray(cts[i]);
      var mac = hexStringToBinaryArray(macs[i]);
  
      ccm.init(false, false, key, macSize, nonce, additionalText);
      // Temporary lib
      var tmp = zeroedData(ct.length);        
      // Process the data 
      var len = ccm.processBytes(ct, 0, ct.length, tmp, 0);  // Destructive to save memory      
      len += ccm.doFinal(tmp, len);
      test.equal(pt.length, len);
      test.deepEqual(pt, tmp.slice(0, len));
      test.deepEqual(mac, ccm.getMac());
    }
  
    test.done();
  }, 
  
  "Test CCM Iv Vectors":function(test) {
    var key = hexStringToBinaryArray("404142434445464748494a4b4c4d4e4f");
    var nonce = hexStringToBinaryArray("10111213141516");
    var pt = binaryStringToArray("hello world!!");
    
    var ccm = new CCM(new AES());
    ccm.init(true, true, key, nonce);
    
    // Set up tmp
    var enc = new Array(pt.length + 8)
    // Process the data
    var len = ccm.processBytes(pt, 0, pt.length, enc, 0);  // Destructive to save memory      
    len += ccm.doFinal(enc, len);
        
    // Decrypt
    ccm.init(false, true, key, nonce);
    // Process the data
    var tmp = new Array(len);
    len = ccm.processBytes(enc, 0, enc.length, tmp, 0);
    len += ccm.doFinal(tmp, len);
    
    test.deepEqual(pt, tmp.slice(0, pt.length));
    test.done();
  },
  
  "Test CCM Reduced associated text":function(test) {
    var additionalText = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    // Key values
    var key = hexStringToBinaryArray("404142434445464748494a4b4c4d4e4f");
    var macSize = 112;
    var nonce = hexStringToBinaryArray("101112131415161718191a1b1c");
    var pt = hexStringToBinaryArray("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    var ct = hexStringToBinaryArray("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");
    var mac = hexStringToBinaryArray("f4dd5d0ee404617225ffe34fce91");
    
    var a4 = new Array(65536);
    a4 = zeroedData(65536);
    // Populate the data array
    for(var i = 0; i < a4.length; i += additionalText.length) {
      util.copy(a4, i, additionalText, 0, additionalText.length);
    }    
    
    // CCM initalize
    var ccm = new CCM(new AES());
    ccm.init(true, false, key, macSize, nonce, a4);
    
    // Set up tmp
    var enc = new Array(ct.length)
    // Process the data
    var len = ccm.processBytes(pt, 0, pt.length, enc, 0);  // Destructive to save memory      
    len += ccm.doFinal(enc, len);
    test.deepEqual(ct, enc);
  
    // Decrypt
    var key = hexStringToBinaryArray("404142434445464748494a4b4c4d4e4f");
    var macSize = 112;
    var nonce = hexStringToBinaryArray("101112131415161718191a1b1c");
    var pt = hexStringToBinaryArray("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    var ct = hexStringToBinaryArray("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");
    var mac = hexStringToBinaryArray("f4dd5d0ee404617225ffe34fce91");    
    // CCM initalize
    ccm.init(false, false, key, macSize, nonce, a4);
    // Temporary lib
    var tmp = zeroedData(ct.length);        
    // Process the data 
    var len = ccm.processBytes(ct, 0, ct.length, tmp, 0);  // Destructive to save memory      
    len += ccm.doFinal(tmp, len);
  
    test.equal(pt.length, len);
    test.deepEqual(pt, tmp.slice(0, len));
    test.deepEqual(mac, ccm.getMac());
    test.done();    
  },
  
  "Test Long CCM data set":function(test) {
    var key = hexStringToBinaryArray("404142434445464748494a4b4c4d4e4f");
    var macSize = 112;
    var nonce = hexStringToBinaryArray("101112131415161718191a1b1c");
    var additionalText = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    var pt = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    var ct = hexStringToBinaryArray("49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3fa5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa8071e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb141d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e854fd3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2dca128f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b51c07beb40e875a87491ec8b27cd1");
    var mac = hexStringToBinaryArray("5c768856796b627b13ec8641581b");    

    // CCM initalize
    var ccm = new CCM(new AES());
    ccm.init(true, false, key, macSize, nonce, additionalText);
    
    // Set up tmp
    var enc = new Array(ct.length)
    // Process the data
    var len = ccm.processBytes(pt, 0, pt.length, enc, 0);  // Destructive to save memory      
    len += ccm.doFinal(enc, len);
    test.deepEqual(ct, enc);

    // Decrypt
    ccm.init(false, false, key, macSize, nonce, additionalText);
    // Temporary lib
    var tmp = zeroedData(ct.length);        
    // Process the data 
    var len = ccm.processBytes(ct, 0, ct.length, tmp, 0);  // Destructive to save memory      
    len += ccm.doFinal(tmp, len);
    test.equal(pt.length, len);
    test.deepEqual(pt, tmp.slice(0, len));    
    test.done();
  }
});


















