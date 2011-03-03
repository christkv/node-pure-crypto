var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// RC5 Implementation in Javascript
const BlockSize = 16;
var ND = 0xFFFFFFFF;

var RC5 = exports.RC5 = function(key, rounds) {
  key = key.slice(0);
  
  // debug(key)
  
  // Pad the key out if it's less than 128 bits
  for(var i = key.length; i < 16; i++) {
    key.push(0);
  }

  var L = new Array(4);
  // Translate key to integers
  for(var i = 0; i < (key.length / 4); i++) {
    var valueArray = key.slice((i * 4), (i * 4 + 4)).reverse();
    L[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
  
  // debug("============================================================ L")
  // debug(L)
  
  var T = 0xb7e15163;
  var S = this.S = new Array((2*rounds));
  // S[0] = T;
  
  for(var i = 0; i < (2*rounds + 2); i++) {
    // debug("================================ T = " + T)
    S[i] = T;
    T = Long.fromNumber(T).add(Long.fromNumber(0x9e3779b9)).getLowBitsUnsigned();
  }
  
  var A = 0;
  var B = 0;
  var numberOfCalculations = (3 * (S.length > L.length ? S.length : L.length)) - 1;

  // var t = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();

  // Set up key
  for(var i = 0; i <= numberOfCalculations; i++) {
    var br = Long.fromNumber(S[i % S.length]).add(Long.fromNumber(A)).add(Long.fromNumber(B)).getLowBitsUnsigned();
    // debug("  A::br::" + br);
    S[i % S.length] = A = Long.fromNumber(rotl(br, 3)).getLowBitsUnsigned();
    // debug(i + "  A = " + A.toString(16));

    br = Long.fromNumber(L[i % L.length]).add(Long.fromNumber(A)).add(Long.fromNumber(B)).getLowBitsUnsigned();
    // debug("  B::br::" + br);
    L[i % L.length] = B = Long.fromNumber(rotl(br, Long.fromNumber(A).add(Long.fromNumber(B)).getLowBitsUnsigned())).getLowBitsUnsigned();
    // debug(i + "  B = " + B.toString(16));
    // debug(" i % S.length = " + (i % S.length));
    // debug(" i % L.length = " + (i % L.length));
    // debug("");
  }  
}

var rotl = function(r, kr) {
  kr = kr & 0x1F
  
  if(kr > 0) {
    return Long.fromNumber((((r & ND) << kr) | ((r &ND) >>> (32 - kr)))).getLowBitsUnsigned();    
  }  
  return r;
}

var rotr = function(r, kr) {
  kr = kr & 0x1F
  
  if(kr > 0) {    
    var a = Long.fromNumber(r).shiftRightUnsigned(kr);
    var b = Long.fromNumber(r).shiftLeft(32-kr);
    return Long.fromNumber(a.getLowBitsUnsigned()&ND | b.getLowBitsUnsigned()&ND).getLowBitsUnsigned();
  }  
  return r;  
}

RC5.prototype.getBlockSize = function() {
  return BlockSize;
}

RC5.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptBlock(src.slice(index));
}

RC5.prototype.encryptBlock = function(input) {
  var regs = new Array(2);
  var S = this.S;
  
  for(var i = 0; i < 2; i ++) {
    var valueArray = input.slice((i * 4), (i * 4 + 4)).reverse();
    regs[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  
  // debug("====== A = " + A)
  // debug("====== B = " + B)
  
  A = Long.fromNumber(A + S[0]).getLowBitsUnsigned();
  B = Long.fromNumber(B + S[1]).getLowBitsUnsigned();

  // debug("====== A = " + A)
  // debug("====== B = " + B)

  for(var i = 1; i <= (S.length - 2); i++) {
    A = Long.fromNumber(S[i + 1]).add(Long.fromNumber(rotl(A ^ B, B))).getLowBitsUnsigned();
    // debug("== A = " + A)
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
    B = Long.fromNumber(B^A).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
  }
  
  // Return the encrypted bytes
  return util.encodeUInt32(A).reverse()
    .concat(util.encodeUInt32(B).reverse());  
}

RC5.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.decryptBlock(src.slice(index));
}

RC5.prototype.decryptBlock = function(input) {
  var regs = new Array(2);
  var S = this.S;
  
  for(var i = 0; i < 2; i ++) {
    var valueArray = input.slice((i * 4), (i * 4 + 4)).reverse();
    regs[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  
  // debug("====== A = " + A)
  // debug("====== B = " + B)
  
  A = Long.fromNumber(A).add(S[0]).getLowBitsUnsigned();
  B = Long.fromNumber(B).add(S[1]).getLowBitsUnsigned();

  // A = Long.fromNumber(A).add(S[0]);
  // B = Long.fromNumber(B).add(S[1]);

  // debug("====== A = " + A)
  // debug("====== B = " + B)

  for(var i = 1; i <= (S.length - 2); i++) {
    // A = Long.fromNumber(S[i + 1]).add(Long.fromNumber(rotl(A ^ B, B))).getLowBitsUnsigned();
    // debug("== A = " + A)
    // A = = Long.fromNumber(A ^ Long.fromNumber(rotr()))
    // var br = Long.fromNumber(B).subtract(Long.fromNumber(S[S.length - i])).toNumber();
    // debug("B = " + B);
    // debug("S[S.length - i] = " + S[S.length - i]);
    var br = Long.fromNumber(B - S[S.length - i]).getLowBitsUnsigned();
    // debug("== opp1 = " + br.toString(16))
    // debug("== opp2 = " + rotr(br, A).toString(16))

    B = Long.fromNumber(A ^ rotr(br, A)).getLowBitsUnsigned();
    // B = Long.fromNumber(A ^ rotr(br, A));
    // debug("== A = " + A)
    // debug("== B = " + B)
    // debug("")

    // A = Long.fromNumber(A.xor(B));
    // B = Long.fromNumber(B.xor(A));
    // A = Long.fromNumber(A.xor(B));

    A = Long.fromNumber(A^B).getLowBitsUnsigned();
    B = Long.fromNumber(B^A).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();

  }

  // debug("====== A = " + A.toString(16))
  // debug("====== B = " + B.toString(16))
    
  A = Long.fromNumber((A - S[0] + MOD) % MOD).getLowBitsUnsigned();
  B = Long.fromNumber((B - S[1] + MOD) % MOD).getLowBitsUnsigned();

  // debug("");
  // debug("====== A = " + A.toString(16))
  // debug("====== B = " + B.toString(16))
    
  // Return the encrypted bytes
  return util.encodeUInt32(A).reverse()
    .concat(util.encodeUInt32(B).reverse());
}

var MOD = 4294967296;



