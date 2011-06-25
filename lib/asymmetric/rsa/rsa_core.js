 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/**
*
*  PKCS#1 encryption-style padding (type 2) En- / Decryption for use in
*  pidCrypt Library. The pidCrypt RSA module is based on the implementation
*  by Tom Wu.
*  See http://www-cs-students.stanford.edu/~tjw/jsbn/ for details and for his
*  great job.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js), BigInteger (jsbn.js),
*  random number generator (rng.js) and a PRNG backend (prng4.js) (the random
*  number scripts are only needed for key generation).
/*----------------------------------------------------------------------------*/
 /*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
 
 var BigInteger = require('./big_integer').BigInteger,
  Random = require('prng/random').Random,
  debug = require('util').debug,
  inspect = require('util').inspect;
 
//Address all questions regarding this license to:
//  Tom Wu
//  tjw@cs.Stanford.EDU
/*----------------------------------------------------------------------------*/
//  Author: Tom Wu
//  tjw@cs.Stanford.EDU
// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
function pkcs1unpad2(d,n) {
  var b = d.toByteArray();
  var i = 0;

  while(i < b.length && b[i] == 0) {
   ++i; 
  }
  
  if(b.length-i != n-1 || b[i] != 2) {
    return null;    
  }
  ++i;

  while(b[i] != 0) {
    if(++i >= b.length) {
      return null;    
    }
  }

  var ret = [];
  var j = 0;
  
  while(++i < b.length) {    
    ret[j++] = b[i] & 0xff;
  }

  return ret;
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) {
    alert("Message too long for RSA");
    return null;
  }
  
  var ba = new Array();
  var i = s.length - 1;
  // while(i >= 0 && n > 0) {ba[--n] = s.charCodeAt(i--);};
  while(i >= 0 && n > 0) {ba[--n] = s[i--];};
  ba[--n] = 0;
  var rng = new Random();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }

  ba[--n] = 2;
  ba[--n] = 0;          
  return new BigInteger(ba);
}

//RSA key constructor
RSA = function() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}
// protected
// Perform raw private operation on "x": return x^d (mod n)
RSA.prototype.doPrivate = function(x) {
if(this.p == null || this.q == null)
return x.modPow(this.d, this.n);

// TODO: re-calculate any missing CRT params
var xp = x.mod(this.p).modPow(this.dmp1, this.p);
var xq = x.mod(this.q).modPow(this.dmq1, this.q);

while(xp.compareTo(xq) < 0)
  xp = xp.add(this.p);
  return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Set the public key fields N and e from hex strings
RSA.prototype.setPublic = function(N,E,radix) {
  if (typeof(radix) == 'undefined') radix = 16;

  if(N != null && E != null && N.length > 0 && E.length > 0) {
  this.n = parseBigInt(N,radix);
  this.e = parseInt(E,radix);
} else
  throw new Error("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
RSA.prototype.doPublic = function(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
RSA.prototype.encryptRaw = function(text) {
  // Add sign before raw encryption
  text = [0].concat(text)
  // Create big integer  
  var m = new BigInteger(text);  
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  return c.toByteArray();
}

RSA.prototype.encrypt = function(text) {
  return this.encryptRaw(text)
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
RSA.prototype.decryptRaw = function(ctext) {
  var c = parseBigInt(ctext, 256);
  var m = this.doPrivate(c);
  if(m == null) return null;  
  var result = m.toByteArray();  
  // Get rid of sign
  if(result[0] == 0) {
    result.shift();    
  }  
  // Return result
  return result;
}

RSA.prototype.decrypt = function(ctext) {
  return this.decryptRaw(ctext)
}

// Set the private key fields N, e, and d from hex strings
RSA.prototype.setPrivate = function(N,E,D,radix) {
  if (typeof(radix) == 'undefined') radix = 16;

  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,radix);
    this.e = parseInt(E,radix);
    this.d = parseBigInt(D,radix);
  } else {
    throw new Error("Invalid RSA private key");
  }
}

// Set the private key fields N, e, d and CRT params from hex strings
RSA.prototype.setPrivateEx = function(N,E,D,P,Q,DP,DQ,C,radix) {
  if (typeof(radix) == 'undefined') radix = 16;

  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,radix);//modulus
    this.e = parseInt(E,radix);//publicExponent
    this.d = parseBigInt(D,radix);//privateExponent
    this.p = parseBigInt(P,radix);//prime1
    this.q = parseBigInt(Q,radix);//prime2
    this.dmp1 = parseBigInt(DP,radix);//exponent1
    this.dmq1 = parseBigInt(DQ,radix);//exponent2
    this.coeff = parseBigInt(C,radix);//coefficient
  } else {
    throw new Error("Invalid RSA private key");
  }
}

// Generate a new random private key B bits long, using public expt E
RSA.prototype.generate = function(B,E) {
  var rng = new Random();
  var qs = B>>1;
  this.e = parseInt(E,16);
  var ee = new BigInteger(E,16);
  for(;;) {
    for(;;) {
      this.p = new BigInteger(B-qs,1,rng);
      if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
    }

    for(;;) {
      this.q = new BigInteger(qs,1,rng);
      if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
    }

    if(this.p.compareTo(this.q) <= 0) {
      var t = this.p;
      this.p = this.q;
      this.q = t;
    }

    var p1 = this.p.subtract(BigInteger.ONE);
    var q1 = this.q.subtract(BigInteger.ONE);
    var phi = p1.multiply(q1);

    if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
      this.n = this.p.multiply(this.q);
      this.d = ee.modInverse(phi);
      this.dmp1 = this.d.mod(p1);
      this.dmq1 = this.d.mod(q1);
      this.coeff = this.q.modInverse(this.p);
      break;
    }
  }
}

exports.RSA = RSA;
