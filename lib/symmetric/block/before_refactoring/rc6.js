var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// RC6 Implementation in Javascript
const BlockSize = 16;
var ND = 0xFFFFFFFF;

var RC6 = exports.RC6 = function(key) {
  var keyLength = key.length;
  key = key.slice(0);
  var L = new Array(8);
  var S = this.S = new Array(44);
  S[0] = 0xB7E15163;
  
  // Translate key to integers
  for(var i = 0; i < (key.length / 4); i++) {
    var valueArray = key.slice((i * 4), (i * 4 + 4)).reverse();
    L[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
    
  for(var i = 1; i < 44; i++) {
    S[i]= S[i - 1] + 0x9E3779B9;    
  }
  
  var A = 0;
  var B = 0;
  var i = 0;
  var j = 0;
  var v = 132;
  
  // Adjust the keyLength
  keyLength >>= 2;
  
  for(var s = 1; s <= v; s++) {
    A = S[i] = rotl((S[i] + A + B), 3);
    B = L[j] = rotl(Long.fromNumber(L[j] + A + B).getLowBitsUnsigned(), Long.fromNumber(A + B).getLowBitsUnsigned());
    i = (i + 1) % 44;
    j = (j + 1) % keyLength;
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

RC6.prototype.getBlockSize = function() {
  return BlockSize;
}

RC6.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  // return this.encryptBlock(src.slice(index, index + BlockSize));
  return this.encryptBlock(src, index);
}

RC6.prototype.encryptBlock = function(input, index) {
  var regs = new Array(4);
  var S = this.S;
  
  for(var i = 0; i < 4; i ++) {
    regs[i] = Long.fromNumber(util.decodeUInt32R(input, index + (i * 4))).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  var C = regs[2];
  var D = regs[3];
  
  B = Long.fromNumber(B + S[0]).getLowBitsUnsigned();
  D = Long.fromNumber(D + S[1]).getLowBitsUnsigned();

  for(var j = 1; j <= 20; j++) {
    // Calculate t
    var br = Long.fromNumber(B).multiply(Long.fromNumber(((B << 1) + 1)));
    var t = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
    // Calculate u
    var br = Long.fromNumber(D).multiply(Long.fromNumber(((D << 1) + 1)));
    var u = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();

    // Calculate A
    A = Long.fromNumber(rotl(Long.fromNumber(A ^ t).getLowBitsUnsigned(), u))
      .add(Long.fromNumber(S[j << 1])).getLowBitsUnsigned();
    // Calculate C
    C = Long.fromNumber(rotl(Long.fromNumber(C ^ u), t))
      .add(Long.fromNumber(S[(j << 1) + 1])).getLowBitsUnsigned();
   
    var temp = A;
    A = B;
    B = C;
    C = D;
    D = temp;
  }
  
  // Adjust the variables
  A = Long.fromNumber(A).add(Long.fromNumber(S[42])).getLowBitsUnsigned();
  C = Long.fromNumber(C).add(Long.fromNumber(S[43])).getLowBitsUnsigned();
    
  // Return the encrypted bytes
  util.inPlaceEncodeUInt32R(A, input, index);
  util.inPlaceEncodeUInt32R(B, input, index + 4);
  util.inPlaceEncodeUInt32R(C, input, index + 8);
  util.inPlaceEncodeUInt32R(D, input, index + 12);
  return input;
}

RC6.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.decryptBlock(src, index);
}

RC6.prototype.decryptBlock = function(input, index) {
  var regs = new Array(4);
  var S = this.S;
  
  for(var i = 0; i < 4; i ++) {
    regs[i] = Long.fromNumber(util.decodeUInt32R(input, index + (i * 4))).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  var C = regs[2];
  var D = regs[3];
  
  C = Long.fromNumber(C - S[43]).getLowBitsUnsigned();
  A = Long.fromNumber(A - S[42]).getLowBitsUnsigned();
  
  for(var j = 20; j >= 1; j--) {
    var temp = A;
    A = D;
    temp2 = B;
    B = temp;
    temp = C;
    C = temp2;
    D = temp;

    // Calculate t
    var br = Long.fromNumber(B).multiply(Long.fromNumber(((B << 1) + 1)));
    var t = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
    // Calculate u
    var br = Long.fromNumber(D).multiply(Long.fromNumber(((D << 1) + 1)));
    var u = Long.fromNumber(rotl(br.getLowBitsUnsigned(), 5)).getLowBitsUnsigned();
    // Calculate A
    var br = Long.fromNumber(A - S[j << 1]).getLowBitsUnsigned();
    A = Long.fromNumber(rotr(br, u) ^ t).getLowBitsUnsigned();
    // Calculate C
    var br = Long.fromNumber(C - S[(j << 1) + 1]).getLowBitsUnsigned();
    C = Long.fromNumber(rotr(br, t) ^ u).getLowBitsUnsigned();
  }
  
  D = Long.fromNumber(D - S[1]).getLowBitsUnsigned();
  B = Long.fromNumber(B - S[0]).getLowBitsUnsigned();
  
  // Return the decrypted bytes
  util.inPlaceEncodeUInt32R(A, input, index);
  util.inPlaceEncodeUInt32R(B, input, index + 4);
  util.inPlaceEncodeUInt32R(C, input, index + 8);
  util.inPlaceEncodeUInt32R(D, input, index + 12);
  return input;
}