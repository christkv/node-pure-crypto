require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  crypto = require('crypto'),
  AES = require('symmetric/block/aesfast').AES,
  CMac = require('mac/cmac').CMac,
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

  "CMac test vectors":function(test) {
    var cipher = new AES();
    var mac = new CMac(cipher, 128)
    
    // Data
    var keyBytes128 = util.hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var input0 = [];
    var outputK128M0 = util.hexStringToBinaryArray("bb1d6929e95937287fa37d129b756746");
    
    // 128 bytes key, 0 bytes message - 128 bytes key
    mac.init(keyBytes128);
    mac.update(input0, 0, input0.length);
    var out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(outputK128M0, out);

    var input16 = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172a");
    var outputK128M16 = util.hexStringToBinaryArray("070a16b46b4d4144f79bdd9dd04a287c");
    // 16 bytes message - 128 bytes key
    mac.init(keyBytes128);
    mac.update(input16, 0, input16.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(outputK128M16, out);
    
    var input40 = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    var output_k128_m40 = util.hexStringToBinaryArray("dfa66747de9ae63030ca32611497c827");
    // 40 bytes message - 128 bytes key
    mac.init(keyBytes128);
    mac.update(input40, 0, input40.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k128_m40, out);
    
    
    var input64 = util.hexStringToBinaryArray("6bc1bee22e409f96e93d7e117393172a"
               + "ae2d8a571e03ac9c9eb76fac45af8e51"
               + "30c81c46a35ce411e5fbc1191a0a52ef"
               + "f69f2445df4f9b17ad2b417be66c3710");
    var output_k128_m64 = util.hexStringToBinaryArray("51f0bebf7e3b9d92fc49741779363cfe");
    // 64 bytes message - 128 bytes key
    mac.init(keyBytes128);
    mac.update(input64, 0, input64.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k128_m64, out);
          
    // 192 bytes key
    var keyBytes192 = util.hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");

    var output_k192_m0 = util.hexStringToBinaryArray("d17ddf46adaacde531cac483de7a9367");    
    // 0 bytes message - 192 bytes key
    mac.init(keyBytes192);
    mac.update(input0, 0, input0.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k192_m0, out);

    var output_k192_m16 = util.hexStringToBinaryArray("9e99a7bf31e710900662f65e617c5184");
    // 16 bytes message - 192 bytes key
    mac.init(keyBytes192);
    mac.update(input16, 0, input16.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k192_m16, out);
    
    var output_k192_m40 = util.hexStringToBinaryArray("8a1de5be2eb31aad089a82e6ee908b0e");
    // 40 bytes message - 192 bytes key
    mac.init(keyBytes192);
    mac.update(input40, 0, input40.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k192_m40, out);

    var output_k192_m64 = util.hexStringToBinaryArray("a1d5df0eed790f794d77589659f39a11");
    // 64 bytes message - 192 bytes key
    mac.init(keyBytes192);
    mac.update(input64, 0, input64.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k192_m64, out);

    // 256 bytes key
    var keyBytes256 = util.hexStringToBinaryArray("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    
    var output_k256_m0 = util.hexStringToBinaryArray("028962f61b7bf89efc6b551f4667d983");
    // 0 bytes message - 256 bytes key
    mac.init(keyBytes256);
    mac.update(input0, 0, input0.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k256_m0, out);
    
    var output_k256_m16 = util.hexStringToBinaryArray("28a7023f452e8f82bd4bf28d8c37c35c");
    // 16 bytes message - 256 bytes key
    mac.init(keyBytes256);
    mac.update(input16, 0, input16.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k256_m16, out);

    var output_k256_m40 = util.hexStringToBinaryArray("aaf3d8f1de5640c232f5b169b9c911e6");
    // 40 bytes message - 256 bytes key
    mac.init(keyBytes256);
    mac.update(input40, 0, input40.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k256_m40, out);

    var output_k256_m64 = util.hexStringToBinaryArray("e1992190549f6ed5696a2c056c315410");
    // 64 bytes message - 192 bytes key
    mac.init(keyBytes256);
    mac.update(input64, 0, input64.length);
    out = zeroedData(16);
    mac.doFinal(out, 0);
    test.deepEqual(output_k256_m64, out);
    test.done();
  }, 
});
