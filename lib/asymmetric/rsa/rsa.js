var debug = require('util').debug
  inspect = require('util').inspect,
  inherits = require('util').inherits,  
  util = require('../../utils'),
  Random = require('prng/random').Random,
  RSA2 = require('./rsa_core').RSA;

var RSA = exports.RSA = function() {  
  this.core = new RSA2();
}

RSA.prototype.init = function(forEncryption, key) {
  this.forEncryption = forEncryption;  
  this.key = key;

  // Set key if it's private
  if(key.isPrivate()) {
    this.core.setPrivateEx(key.modulus.toString(16), key.e.toString(16),
      key.exponent.toString(16), key.p.toString(16),
      key.q.toString(16), key.dP.toString(16),
      key.dQ.toString(16),
      key.qInv.toString(16), 16)    
  } else {
    this.core.setPublic(key.modulus.toString(16), key.exponent.toString(16), 16)
  }  
}

RSA.prototype.getInputBlockSize = function() {
  var bitSize = this.key.modulus.bitLength();  
  return this.forEncryption ? Math.floor((bitSize + 7) / 8 - 1) : Math.floor((bitSize + 7) / 8);
}

RSA.prototype.getOutputBlockSize = function() {
  var bitSize = this.key.modulus.bitLength();  
  return this.forEncryption ? Math.floor((bitSize + 7) / 8) : Math.floor((bitSize + 7) / 8 - 1);
}

RSA.prototype.processBlock = function(input, inOff, inLen) {
  if(this.forEncryption) {
    return this.core.encrypt(input);
  } else {
    return this.core.decrypt(input);    
  }
}

// // RSACORE
// var RSACore = function() {
// }
// 
// RSACore.prototype.init = function(forEncryption, key) {
//   this.forEncryption = forEncryption;
//   this.key = key;  
// }
// 
// RSACore.prototype.getInputBlockSize = function() {
//   var bitSize = this.key.modulus.bitLength();  
//   return this.forEncryption ? Math.floor((bitSize + 7) / 8 - 1) : Math.floor((bitSize + 7) / 8);
// }
// 
// RSACore.prototype.getOutputBlockSize = function() {
//   var bitSize = this.key.modulus.bitLength();  
//   return this.forEncryption ? Math.floor((bitSize + 7) / 8) : Math.floor((bitSize + 7) / 8 - 1);
// }
// 
// RSACore.prototype.convertInput = function(input, inOff, inLen) {
//   if(inLen > (this.getInputBlockSize() + 1)) {
//     throw new Error("input too large for RSA cipher.");
//   } else if(inLen == (this.getInputBlockSize() + 1) && !this.forEncryption) {
//     throw new Error("input too large for RSA cipher.");
//   }
//   
//   var block = [];
//   
//   if(inOff != 0 || inLen != input.length) {
//     block = input.slice(inOff, inOff + inLen);
//   } else {
//     block = input;
//   }
// 
//   var res = new BigInteger(util.toHex(block), 16);
//   if(res.compareTo(this.key.modulus) > 0) {
//     throw new Error("input too large for RSA cipher.");
//   }
//   
//   return res;
// }
// 
// RSACore.prototype.convertOutput = function(result) {  
//   result = result.toString(16);
//   
//   var output = (result.length % 2) == 1 ? util.hexStringToBinaryArray('0' + result) : util.hexStringToBinaryArray(result);
//   
//   if(this.forEncryption) {
//     if(output[0] == 0 && output.length > this.getOutputBlockSize()) {
//       return output.slice(1, output.length);
//     }
//     
//     if(output.length < this.getOutputBlockSize()) {
//       var tmp = new Array(this.getOutputBlockSize());
//       util.copy(tmp, (tmp.length - output.length), output, 0, output.length);
//       return tmp;
//     }
//   } else {
//     if(output[0] == 0) {
//       return output.slice(1, output.length);
//     }
//   }
//   
//   return output;
// }
// 
// RSACore.prototype.processBlock = function(input) {
//   if(this.key.isPrivate()) {
//     var p = this.key.p;
//     var q = this.key.q;
//     var dP = this.key.dP;
//     var dQ = this.key.dQ;
//     var qInv = this.key.qInv;
//     
//     var mP = (input.remainder(p)).modPow(dP, p);
// 
//     var mQ = (input.remainder(q)).modPow(dQ, q);
// 
//     var h = mP.subtract(mQ);
//     h = h.multiply(qInv);
//     h = h.mod(p);
//     
//     var m = h.multiply(q);
//     m = m.add(mQ);
//     
//     return m;
//   } else {
//     return input.modPow(this.key.exponent, this.key.modulus);
//   }
// }

var RSAPublicKey = exports.RSAPublicKey = function(private, modulus, exponent) {
  this.private = private;
  this.modulus = modulus;
  this.exponent = exponent;
}

RSAPublicKey.prototype.isPrivate = function() { return false; }

var RSAPrivateKey = exports.RSAPrivateKey = function(modulus, publicExponent, privateExponent, p, q, dP, dQ, qInv) {
  RSAPublicKey.call(this, true, modulus, privateExponent);
  
  this.e = publicExponent;
  this.p = p;
  this.q = q;
  this.dP = dP;
  this.dQ = dQ;
  this.qInv = qInv;
}

inherits(RSAPrivateKey, RSAPublicKey);

RSAPrivateKey.prototype.isPrivate = function() { return true; }
