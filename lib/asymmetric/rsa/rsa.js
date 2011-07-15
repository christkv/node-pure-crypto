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
