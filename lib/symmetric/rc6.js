var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long;

// RC6 Implementation in Javascript
const BlockSize = 8;
var ND = 0xFFFFFFFF;

var RC6 = exports.RC6 = function(key) {
  var keyLength = key.length;
  key = key.slice(0);
  var L = new Array(8);
  var S = this.S = new Array(44);
  S[0] = 0xB7E15163;
  
  // Pad out key if we have less than 32 bytes (256)
  if(key.length < 32) {
    for(var i = key.length; i < 32; i++) {
      key.push(0);
    }
  }
  
  // debug("========================================== key bytes\n");
  // for(var i = 0; i < 32; i++) {
  //   debug("== " + key[i]);
  // }
  
  
  // debug("=========================================== L");
  // Translate key to integers
  for(var i = 0; i < 8; i ++) {
    var valueArray = key.slice((i * 4), (i * 4 + 4)).reverse();
    // debug(valueArray)
    L[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
    // L[i] = Long.fromNumber(util.decodeUInt32(key, (i * 4))).getLowBitsUnsigned();
    // debug("== " + L[i]);
  }
  // for()  
  // for(var i = 0; i < 8; i++) {
  //   L[i] = 0;
  // }
  
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
    // debug("rotl((S[i] + A + B), 3) = " + (rotl((S[i] + A + B), 3)))
    // debug("rotl((L[j] + A + B), (A + B)) = " + (rotl((L[j] + A + B), (A + B))))
  
    // debug("A before = " + A);
    // debug("B before = " + B);
    
    A = S[i] = rotl((S[i] + A + B), 3);
    // A = S[i];
    // debug("L[j] = " + L[j]);
    // debug("(L[j] + A + B) = " + Long.fromNumber(L[j] + A + B).getLowBitsUnsigned());
    B = L[j] = rotl(Long.fromNumber(L[j] + A + B).getLowBitsUnsigned(), Long.fromNumber(A + B).getLowBitsUnsigned());
    // B = L[j];
    
    // debug("A after = " + A);
    // debug("B after = " + B);
    
    i = (i + 1) % 44;
    j = (j + 1) % keyLength;
  }
  
  // var l_key = new Array(key.length);
  // var l = new Array(8);
  // 
  // l_key[0] = 0xb7e15163;
  // 
  // for(var k = 1; k < 44; ++k) {
  //   l_key[k] = Long.fromNumber(l_key[k - 1] + 0x9e3779b9).getLowBitsUnsigned();
  // }
  // 
  // for(var k = 1; k < (key.length*8)/32; ++k) {
  //   l[k] = key[k];
  // }
  // 
  // // t = (key_len / 32);
  // var t = ((key.length*8)/32) - 1;   
  // var a = 0, b = 0, i = 0, j = 0;
  // 
  // for(var k = 0; k < 132; ++k) {
  //   a = rotl(l_key[i] + a + b, 3);
  //   b += a;
  //   b = rotl(l[j] + b, b);
  //   l_key[i] = a;
  //   l[j] = b;
  //   // i = (i + 1) % 44;  
  //   i = (i == 43 ? 0 : i + 1);
  //   // j = (j + 1) % t;
  //   j = (j == t ? 0 : j + 1);
  // }
  // 
  // this.l_key = l_key;
  debug("------------------------------------------------------------- S")
  debug(S)
}

var rotl = function(r, kr) {
  // debug("  -- r = " + r);
  // debug("  -- kr = " + (kr & 0x1F));
  kr = kr & 0x1F
  
  // return Long.fromNumber(r).shiftLeft(kr).xor(Long.fromNumber(r).shiftRightUnsigned(32 - kr)).getLowBitsUnsigned();
  
  // //(((x) << ((n) & 0x1F)) | ((x) >> (32 - ((n) & 0x1F))))
  // return Long.fromNumber((((r) << kr) ^ ((r&ND) >>> (32 - kr)))).getLowBitsUnsigned();

  if(kr > 0) {
    return Long.fromNumber((((r & ND) << kr) ^ ((r &ND) >>> (32 - kr)))).getLowBitsUnsigned();    
  }
  
  return r;
  
  // var i = r;
  // // If no rotation
  // if(kr > 0) {
    // i = Long.fromNumber((((r&ND) << kr) ^ ((r&ND) >>> (32 - kr)))&ND).getLowBitsUnsigned();
  // }    
  // return i;
}


RC6.prototype.keySchedule = function(inn) {
}

RC6.prototype.getBlockSize = function() {
  return BlockSize;
}

RC6.prototype.encrypt = function(src, index) {
  index = index == null ? 0 : index;
  return this.encryptBlock(src.slice(index));
}

RC6.prototype.encryptBlock = function(input) {
  var regs = new Array(4);
  var S = this.S;
  
  for(var i = 0; i < 4; i ++) {
    var valueArray = input.slice((i * 4), (i * 4 + 4)).reverse();
    regs[i] = Long.fromNumber(util.decodeUInt32(valueArray, 0)).getLowBitsUnsigned();
  }
  
  var A = regs[0];
  var B = regs[1];
  var C = regs[2];
  var D = regs[3];
  
  // debug("-- A=" + A);
  // debug("-- B=" + B);
  // debug("-- C=" + C);
  // debug("-- D=" + D);
  // debug("-- S[0]=" + S[0]);
  // debug("-- S[1]=" + S[1]);
  
  B = Long.fromNumber(B + S[0]).getLowBitsUnsigned();
  D = Long.fromNumber(D + S[1]).getLowBitsUnsigned();

  // debug("-- B=" + B);
  // debug("-- D=" + D);
  
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
   
    // debug("  -- t="+ t);
    // debug("  -- u="+ u);
    // debug("  -- A="+ A);
    // debug("  -- C="+ C);
    // debug("");
   
    var temp = A;
    A = B;
    B = C;
    C = D;
    D = temp;
  }
  
  // Adjust the variables
  A = Long.fromNumber(A).add(Long.fromNumber(S[42])).getLowBitsUnsigned();
  C = Long.fromNumber(C).add(Long.fromNumber(S[43])).getLowBitsUnsigned();
  
  debug("  -- A="+ A);
  debug("  -- B="+ B);
  debug("  -- C="+ C);
  debug("  -- D="+ D);
  
  // Return the encrypted bytes
  return util.encodeUInt32(A).reverse()
    .concat(util.encodeUInt32(B).reverse())
    .concat(util.encodeUInt32(C).reverse())
    .concat(util.encodeUInt32(D).reverse());
}

RC6.prototype.decrypt = function(src, index) {
  index = index == null ? 0 : index;
  // return this.decryptBlock(src.slice(index));
}