var debug = require('util').debug
  inspect = require('util').inspect,
  // BigInteger = require('big_integer').BigInteger,
  BigInteger = require('big_decimal').BigInteger,
  Random = require('prng/random').Random;

// debug(inspect(new BigInteger2()))

var RSA = exports.RSA = function(N, E, D, P, Q, DP, DQ, C) {  
  // // public key
  // this.e = 0;              // public exponent. must be <2^31
  // this.n; // modulus
  // // private key
  // this.d;
  // // extended private key
  // this.p;
  // this.q;
  // this.dmp1
  // this.dmq1;
  // this.coeff;
  // // flags. flags are cool.
  // this.canDecrypt;
  // this.canEncrypt;
  
  this.n = N;
  this.e = E;
  this.d = D;
  this.p = P;
  this.q = Q;
  this.dmp1 = DP;
  this.dmq1 = DQ;
  this.coeff = C;
  
	// adjust a few flags.
	this.canEncrypt = (this.n != null && this.e != 0);
	this.canDecrypt = (this.canEncrypt && this.d != null);  
}

RSA.parsePrivateKey = function(N, E, D, P, Q, DMP1, DMQ1, IQMP) {
  if(P == null) {
    return new RSA(new BigInteger(N, 16), new BigInteger(E, 16), new BigInteger(D,16));
	} else {
    // debug(inspect(new BigInteger(N, 16)))
    
    var a = new BigInteger(N, 16);
    var b = new BigInteger(N, 16);
    var c = a.add(b);
    debug(c.toString())
	  
    return new RSA(new BigInteger(N, 16), parseInt(E,16), new BigInteger(D,16),
     new BigInteger(P, 16), new BigInteger(Q, 16),
     new BigInteger(DMP1, 16), new BigInteger(DMQ1, 16),
     new BigInteger(IQMP, 16));
	}
}

RSA.prototype.encrypt = function(src, sindex, dst, dindex, length, pad) {
  _encrypt(this, doPublic, src, sindex, dst, dindex, length, pad, 0x02);
}

RSA.prototype.decrypt = function() {
  
}

RSA.prototype.getBlockSize = function() {
  return (this.n.bitLength()+7)/8;
}

var _encrypt = function(self, op, src, sindex, dst, dindex, length, pad, padType) {
	// adjust pad if needed
	if(pad==null) pad = pkcs1pad;

	// convert src to BigInteger
	if(sindex >= src.length) {
		sindex = 0;
	}
	
	var bl = Math.floor(self.getBlockSize());
	var end = sindex + length;

  debug(bl)
  debug(end)

	while(sindex < end) {
    debug("================================================== 1")
		var padResult = pad(src, sindex, end, bl, padType);
		var block = new BigInteger(util.toHex(util.arrayToBinaryString(padResult)), bl);
    debug("================================================== 2")
		
		
		var chunk = op(self, block);
    // debug("======================= chunk :: " + inspect(chunk))
    var result = chunk.toByteArray();
    // debug("=== result :: " + inspect(result))
    
    // var copy = exports.copy = function(targetArray, destIndex, sourceArray, sourceIndex, sourceLength) {
    util.copy(dst, dindex, result, 0, result.length);
    dindex = dindex + result.length;
    sindex = sindex + result.length;
    // sindex += chunk.toByteArray();
	}  
}

var doPublic = function(self, x) {
  return x.modPowInt(self.e, self.n);
}

/**
 * PKCS#1 pad. type 1 (0xff) or 2, random.
 * puts as much data from src into it, leaves what doesn't fit alone.
 */
var pkcs1pad = function(src, sindex, end, n, _type) {
  _type = _type == null ? 0x02 : _type;
	var out = [];
	var p = sindex;
	end = Math.min(end, src.length, p+n-11);
	sindex = end;

	var i = end - 1;
	while (i >= p && n > 11) {
		out[--n] = src[i--];
	}

	out[--n] = 0;

	if (_type == 0x02) { // type 2
		var rng = new Random;
		var x = 0;
		while (n>2) {
			do {
				x = rng.nextByte();
			} while (x==0);
			out[--n] = x;
		}				
	} else { // type 1
		while (n>2) {
			out[--n] = 0xFF;
		}
	}
	
	out[--n] = _type;
	out[--n] = 0;	
	return out;
}

