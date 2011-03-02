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
  
  debug("====== A = " + A)
  debug("====== B = " + B)
  
  A = Long.fromNumber(A + S[0]).getLowBitsUnsigned();
  B = Long.fromNumber(B + S[1]).getLowBitsUnsigned();

  debug("====== A = " + A)
  debug("====== B = " + B)

  for(var i = 1; i <= (S.length - 2); i++) {
    A = Long.fromNumber(S[i + 1]).add(Long.fromNumber(rotl(A ^ B, B))).getLowBitsUnsigned();
    debug("== A = " + A)
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
    B = Long.fromNumber(B^A).getLowBitsUnsigned();
    A = Long.fromNumber(A^B).getLowBitsUnsigned();
  }
  
  // Return the encrypted bytes
  return util.encodeUInt32(A).reverse()
    .concat(util.encodeUInt32(B).reverse());  
  
  // B = Long.fromNumber(B + S[0]).getLowBitsUnsigned();
  // D = Long.fromNumber(D + S[1]).getLowBitsUnsigned();
  // 
  // for(var j = 1; j <= 20; j++) {
  //   // Calculate t
  //   var br = Long.fromNumber(B).multiply(Long.fromNumber(((B << 1) + 1)));
  //   var t = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
  //   // Calculate u
  //   var br = Long.fromNumber(D).multiply(Long.fromNumber(((D << 1) + 1)));
  //   var u = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
  // 
  //   // Calculate A
  //   A = Long.fromNumber(rotl(Long.fromNumber(A ^ t).getLowBitsUnsigned(), u))
  //     .add(Long.fromNumber(S[j << 1])).getLowBitsUnsigned();
  //   // Calculate C
  //   C = Long.fromNumber(rotl(Long.fromNumber(C ^ u), t))
  //     .add(Long.fromNumber(S[(j << 1) + 1])).getLowBitsUnsigned();
  //  
  //   var temp = A;
  //   A = B;
  //   B = C;
  //   C = D;
  //   D = temp;
  // }
  // 
  // // Adjust the variables
  // A = Long.fromNumber(A).add(Long.fromNumber(S[42])).getLowBitsUnsigned();
  // C = Long.fromNumber(C).add(Long.fromNumber(S[43])).getLowBitsUnsigned();
  //   
  // // Return the encrypted bytes
  // return util.encodeUInt32(A).reverse()
  //   .concat(util.encodeUInt32(B).reverse())
  //   .concat(util.encodeUInt32(C).reverse())
  //   .concat(util.encodeUInt32(D).reverse());
}

RC5.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.decryptBlock(src.slice(index));
}

RC5.prototype.decryptBlock = function(input) {
  // var regs = new Array(4);
  // var S = this.S;
  // 
  // for(var i = 0; i < 4; i ++) {
  //   var valueArray = input.slice((i * 4), (i * 4 + 4)).reverse();
  //   regs[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  // }
  // 
  // var A = regs[0];
  // var B = regs[1];
  // var C = regs[2];
  // var D = regs[3];
  // 
  // C = Long.fromNumber(C - S[43]).getLowBitsUnsigned();
  // A = Long.fromNumber(A - S[42]).getLowBitsUnsigned();
  // 
  // for(var j = 20; j >= 1; j--) {
  //   var temp = A;
  //   A = D;
  //   temp2 = B;
  //   B = temp;
  //   temp = C;
  //   C = temp2;
  //   D = temp;
  // 
  //   // Calculate t
  //   var br = Long.fromNumber(B).multiply(Long.fromNumber(((B << 1) + 1)));
  //   var t = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
  //   // Calculate u
  //   var br = Long.fromNumber(D).multiply(Long.fromNumber(((D << 1) + 1)));
  //   var u = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
  //   // Calculate A
  //   var br = Long.fromNumber(A - S[j << 1]).getLowBitsUnsigned();
  //   A = Long.fromNumber(rotr(br, u) ^ t).getLowBitsUnsigned();
  //   // Calculate C
  //   var br = Long.fromNumber(C - S[(j << 1) + 1]).getLowBitsUnsigned();
  //   C = Long.fromNumber(rotr(br, t) ^ u).getLowBitsUnsigned();
  // }
  // 
  // D = Long.fromNumber(D - S[1]).getLowBitsUnsigned();
  // B = Long.fromNumber(B - S[0]).getLowBitsUnsigned();
  // 
  // // Return the encrypted bytes
  // return util.encodeUInt32(A).reverse()
  //   .concat(util.encodeUInt32(B).reverse())
  //   .concat(util.encodeUInt32(C).reverse())
  //   .concat(util.encodeUInt32(D).reverse());
}