var debug = require('util').debug
  inspect = require('util').inspect,
  inherits = require('util').inherits,  
  util = require('../../utils'),
  BigInteger = require('big_decimal').BigInteger,
  Random = require('prng/random').Random;

var RSA = exports.RSA = function(forEncryption, key) {  
  this.core = new RSACore(forEncryption, key);
}

RSA.prototype.inputBlockSize = function() {
  return this.core.inputBlockSize();
}

RSA.prototype.outputBlockSize = function() {
  return this.core.outputBlockSize();
}

RSA.prototype.processBlock = function(input, inOff, inLen) {
  return this.core.convertOutput(this.core.processBlock(this.core.convertInput(input, inOff, inLen)));
}

var RSACore = function(forEncryption, key) {
  this.forEncryption = forEncryption;
  this.key = key;
}

RSACore.prototype.inputBlockSize = function() {
  var bitSize = this.key.modulus.bitLength();  
  return this.forEncryption ? Math.floor((bitSize + 7) / (8 - 1)) : Math.floor((bitSize + 7) / 8);
}

RSACore.prototype.outputBlockSize = function() {
  var bitSize = this.key.modulus.bitLength();  
  return this.forEncryption ? Math.floor((bitSize + 7) / 8) : Math.floor((bitSize + 7) / (8 - 1));
}

RSACore.prototype.convertInput = function(input, inOff, inLen) {
  // debug("============================================= convertInput")
  if(inLen > (this.inputBlockSize() + 1)) {
    throw new Error("input too large for RSA cipher.");
  } else if(inLen == (this.inputBlockSize() + 1) && !this.forEncryption) {
    throw new Error("input too large for RSA cipher.");
  }
  
  // debug("=================================================== 1")
  
  var block = [];
  
  if(inOff != 0 || inLen != input.length) {
    block = input.slice(inOff, inOff + inLen);
  } else {
    block = input;
  }

  // debug("=================================================== 1")
  // debug(inspect(block))
  
  var res = new BigInteger(util.toHex(block), 16);
  // debug("=================================================== 1")
  if(res.compareTo(this.key.modulus) > 0) {
    throw new Error("input too large for RSA cipher.");
  }

  
  return res;
}

RSACore.prototype.convertOutput = function(result) {
  // debug(inspect(result.toString(16)))
  // 
  // debug("============================================= convertOutput")
  var output = util.hexStringToBinaryArray(result.toString(16));
  // debug(output.length)
  // debug(this.outputBlockSize())
  
  
  if(this.forEncryption) {
    if(output[0] == 0 && output.length > this.outputBlockSize()) {
      return output.slice(1, output.length);
    }
    
    if(output.length < this.outputBlockSize()) {
      var tmp = new Array(this.outputBlockSize());
      util.copy(tmp, (tmp.length - output.length), output, 0, output.length);
      return tmp;
    }
  } else {
    if(output[0] == 0) {
      return output.slice(1, output.length);
    }
  }
  
  return output;
}

RSACore.prototype.processBlock = function(input) {
  // debug("============================================= processBlock")
  
  if(this.key instanceof RSAPrivateKey) {
    // debug("=================================================1")
    var p = this.key.p;
    var q = this.key.q;
    var dP = this.key.dP;
    var dQ = this.key.dQ;
    var qInv = this.key.qInv;
    
    // debug("=================================================2")
    // mP = ((input mod p) ^ dP)) mod p
    // debug("============================= p :: " + inspect(this.key))
    
    var mP = (input.remainder(p)).modPow(dP, p);

    // debug("=================================================3")
    // mQ = ((input mod q) ^ dQ)) mod q
    var mQ = (input.remainder(q)).modPow(dQ, q);

    // h = qInv * (mP - mQ) mod p    
    var h = mP.subtract(mQ);
    h = h.multiply(qInv);
    h = h.mod(p);
    
    // m = h * q + mQ
    var m = h.multiply(q);
    m = m.add(mQ);
    return m;
  } else {
    return input.modPow(this.key.exponent, this.key.modulus);
  }
}

var RSAPublicKey = exports.RSAPublicKey = function(private, modulus, exponent) {
  this.private = private;
  this.modulus = modulus;
  this.exponent = exponent;
}

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
