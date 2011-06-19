require.paths.unshift("./lib");

var TestSuite = testCase = require('../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../deps/nodeunit'),
  BigInteger = require('big_decimal').BigInteger,
  RSA = require('asymmetric/rsa/rsa').RSA,
  RSAPublicKey = require('asymmetric/rsa/rsa').RSAPublicKey,
  RSAPrivateKey = require('asymmetric/rsa/rsa').RSAPrivateKey,
  // PEM = require('asymmetric/util/pem').PEM,
  util = require('utils'),
  crypto = require('crypto');
    
var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
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

  "Should correctly handle strict PKCS1 Length": function(test) {
    var pubKey = new RSAPublicKey(false, mod, pubExp);
    var privateKey = new RSAPrivateKey(mod, pubExp, privExp, p, q, pExp, qExp, crtCoef);    
    var data = hexStringToBinaryArray(edgeInput);

    // debug("--------------------------------------------------------")
    // // debug(inspect(data))
    // 
    // for(var i = 0; i < data.length; i++) {
    //   debug("[" + i + "] = " + data[i])
    // }
    
    // Create rsa key
    var rsa = new RSA(true, pubKey);
    // Encrypt
    data = rsa.processBlock(data, 0, data.length);
    
    // debug("--------------------------------------------------------")
    // // debug(inspect(data))
    // 
    // for(var i = 0; i < data.length; i++) {
    //   debug("[" + i + "] = " + data[i])
    // }
    
    rsa = new RSA(false, privateKey);
    data = rsa.processBlock(data, 0, data.length);
    
    // debug("--------------------------------------------------------")
    // for(var i = 0; i < data.length; i++) {
    //   debug("[" + i + "] = " + data[i])
    // }
    
    test.deepEqual(hexStringToBinaryArray(edgeInput), data);
    
    
    // var N = "C4E3F7212602E1E396C0B6623CF11D26204ACE3E7D26685E037AD2507DCE82FC" + 
    //    "28F2D5F8A67FC3AFAB89A6D818D1F4C28CFA548418BD9F8E7426789A67E73E41";
    // var E = "10001";
    // var D = "7cd1745aec69096129b1f42da52ac9eae0afebbe0bc2ec89253598dcf454960e" + 
    //    "3e5e4ec9f8c87202b986601dd167253ee3fb3fa047e14f1dfd5ccd37e931b29d";
    // var P = "f0e4dd1eac5622bd3932860fc749bbc48662edabdf3d2826059acc0251ac0d3b";
    // var Q = "d13cb38fbcd06ee9bca330b4000b3dae5dae12b27e5173e4d888c325cda61ab3";
    // var DMP1 = "b3d5571197fc31b0eb6b4153b425e24c033b054d22b9c8282254fe69d8c8c593";
    // var DMQ1 = "968ffe89e50d7b72585a79b65cfdb9c1da0963cceb56c3759e57334de5a0ac3f";
    // var IQMP = "d9bc4f420e93adad9f007d0e5744c2fe051c9ed9d3c9b65f439a18e13d6e3908";
    // 
    // // create a key.
    // var rsa = RSA.parsePrivateKey(N,E,D, P,Q,DMP1,DMQ1,IQMP);
    // var txt = "hello";
    // var src = util.binaryStringToArray(txt);
    // var dst = [];
    // var dst2 = [];
    // 
    // debug(inspect(src))
    // rsa.encrypt(src, 0, dst, 0, src.length);   
    // debug(inspect(dst))
		
    // rsa.decrypt(dst, 0, dst2, 0, dst.length);
    // var txt2 = util.toHex(dst2);
    // assert("rsa encrypt+decrypt", txt==txt2);
    
    test.done();
  },      
});