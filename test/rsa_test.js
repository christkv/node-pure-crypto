require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  BigInteger = require('big_decimal').BigInteger,
  RSA = require('asymmetric/rsa/rsa').RSA,
  RSAPublicKey = require('asymmetric/rsa/rsa').RSAPublicKey,
  RSAPrivateKey = require('asymmetric/rsa/rsa').RSAPrivateKey,
  PKCS1 = require('asymmetric/pkcs1').PKCS1,
  util = require('utils'),
  crypto = require('crypto'),
  BigInteger = require('asymmetric/rsa/big_integer').BigInteger,
  RSA2 = require('asymmetric/rsa/rsa_core').RSA,
  utils = require('../lib/utils');
    
var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
}

var toHex = exports.toHex = function(array) {
  var s = "";
  for(var i = 0; i < array.length; i++) {
    var v = array[i].toString(16);
    if(v.length == 1) v = "0" + v; 
    s += v.toUpperCase();
  }
  return s;
}

const mod = new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16);
const pubExp = new BigInteger("11", 16);
const privExp = new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16);
const p = new BigInteger("f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03", 16);
const q = new BigInteger("b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947", 16);
const pExp = new BigInteger("1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5", 16);
const qExp = new BigInteger("6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded", 16);
const crtCoef = new BigInteger("dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339", 16);

const input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

//
// to check that we handling byte extension by big number correctly.
//
const edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

const oversizedSig = hexStringToBinaryArray("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
const dudBlock = hexStringToBinaryArray("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
const truncatedDataBlock = hexStringToBinaryArray("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
const incorrectPadding = hexStringToBinaryArray("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e");
const missingDataBlock = hexStringToBinaryArray("0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Should correctly encrypt/decrypt using edge data to correctly handle byte extension by big number": function(test) {    
    var rsa = new RSA2();

    // Set the public key fields N and e from hex strings
    // RSA.prototype.setPublic = function(N,E,radix) {
    rsa.setPublic("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
      "11", 16);
  
    var res = rsa.encrypt(utils.hexStringToBinaryArray(edgeInput))
    // Set the private key fields N, e, d and CRT params from hex strings
    // RSA.prototype.setPrivateEx = function(N,E,D,P,Q,DP,DQ,C,radix) {
    rsa.setPrivateEx("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5",
      "11", "92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619",
      "f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03",
      "b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947",
      "1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5",
      "6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded",
      "dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339",
      16)

    var rs2 = rsa.decrypt(res);
    test.deepEqual(utils.hexStringToBinaryArray(edgeInput), rs2);    
    test.done();
  },
  
  "Should correctly encrypt/decrypt using edge data to correctly handle byte extension by big number": function(test) {
    var pubKey = new RSAPublicKey(false, mod, pubExp);
    var privateKey = new RSAPrivateKey(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);    
    var data = hexStringToBinaryArray(edgeInput); 
  
    // Create rsa key
    var rsa = new RSA();
    rsa.init(true, pubKey)
  
    // Encrypt
    data = rsa.processBlock(data, 0, data.length);    
  
    rsa = new RSA();
    rsa.init(false, privateKey);
    data = rsa.processBlock(data, 0, data.length);
  
    // debug(inspect(data))
    test.deepEqual(hexStringToBinaryArray(edgeInput), data);
    test.done();
  },
  
  "Should correc encrypt/decrypt simple input": function(test) {
    var pubKey = new RSAPublicKey(false, mod, pubExp);
    var privateKey = new RSAPrivateKey(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);    
    var data = hexStringToBinaryArray(input); 
  
    // Create rsa key
    var rsa = new RSA();
    rsa.init(true, pubKey);
    // Encrypt
    data = rsa.processBlock(data, 0, data.length);
    
    rsa = new RSA();
    rsa.init(false, privateKey);
    data = rsa.processBlock(data, 0, data.length);
    test.deepEqual(hexStringToBinaryArray(input), data);
    test.done();    
  },  
  
  "Should correctly encrypt/decrypt data using pkcs1": function(test) {
    var pubKey = new RSAPublicKey(false, mod, pubExp);
    var privateKey = new RSAPrivateKey(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);    
    var data = hexStringToBinaryArray(input); 
    
    // Create rsa key
    var rsa = new RSA();
    var eng = new PKCS1(rsa);
    eng.init(true, pubKey);
  
    // Encrypt
    var data = eng.processBlock(data, 0, data.length);
  
    // Decrypt
    eng.init(false, privateKey);
    data = eng.processBlock(data, 0, data.length);
  
    // Test
    test.deepEqual(hexStringToBinaryArray(input), data);
    test.done();    
  },
});