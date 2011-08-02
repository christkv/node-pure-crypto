var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  Long = require('long').Long,
  Serpent = require('symmetric/block/serpent').Serpent;

var Sosemanuk = exports.Sosemanuk = function() {
}

Sosemanuk.prototype.init = function(forEncryption, key, iv) {
  var k = this.key = Serpent.keySchedule(key, 24);
  var m_state = this.m_state = new Array(12);
  for(var i = 0; i < m_state.length; i++) m_state[i] = 0;
  
  // Set up parameters
  var a = 0, b = 0, c = 0, d = 0, e = 0;
  
  // Let's set up the iv :)
  a = util.decodeUInt32R(iv, 0);
  b = util.decodeUInt32R(iv, 4);
  c = util.decodeUInt32R(iv, 8);
  d = util.decodeUInt32R(iv, 12);
  
  var i = 1;
  var values = [k, [a, b, c, d, e]];  
  var index = 0;
  
  do {
    values = Serpent.beforeS0(values, index, Serpent.KX);
    values = Serpent.beforeS0(values, index, Serpent.S0);
    values = Serpent.afterS0(values, index, Serpent.LT);
    values = Serpent.afterS0(values, index, Serpent.KX);
    values = Serpent.afterS0(values, index, Serpent.S1);
    values = Serpent.afterS1(values, index, Serpent.LT);
    
    // after 18th round
    if(i == 3) { 
      m_state[4] = values[1][1];
      m_state[5] = values[1][4];
      m_state[10] = values[1][2];
      m_state[11] = values[1][0];
    } 
    
    values = Serpent.afterS1(values, index, Serpent.KX);
    values = Serpent.afterS1(values, index, Serpent.S2);
    values = Serpent.afterS2(values, index, Serpent.LT);
    values = Serpent.afterS2(values, index, Serpent.KX);
    values = Serpent.afterS2(values, index, Serpent.S3);
    values = Serpent.afterS3(values, index, Serpent.LT);
    
    // after 12th round
    if(i == 2) {
      m_state[6] = values[1][2];
      m_state[7] = values[1][3];
      m_state[8] = values[1][1];
      m_state[9] = values[1][4];
    }

    values = Serpent.afterS3(values, index, Serpent.KX);
    values = Serpent.afterS3(values, index, Serpent.S4);
    values = Serpent.afterS4(values, index, Serpent.LT);
    values = Serpent.afterS4(values, index, Serpent.KX);
    values = Serpent.afterS4(values, index, Serpent.S5);
    values = Serpent.afterS5(values, index, Serpent.LT);
    values = Serpent.afterS5(values, index, Serpent.KX);
    values = Serpent.afterS5(values, index, Serpent.S6);
    values = Serpent.afterS6(values, index, Serpent.LT);
    values = Serpent.afterS6(values, index, Serpent.KX);
    values = Serpent.afterS6(values, index, Serpent.S7);
    values = Serpent.afterS7(values, index, Serpent.LT);
    
    if(i == 3) {
      break;
    }
    
    ++i;
    values[1][2] = values[1][1];
    values[1][1] = values[1][4];
    values[1][4] = values[1][3];
    values[1][3] = values[1][0];
    values[1][0] = values[1][4];
    index = index + 32;    
  } while(true)  
  
  values = Serpent.afterS7(values, index, Serpent.KX);
  // Set up state
  m_state[0] = values[1][0];
  m_state[1] = values[1][1];
  m_state[2] = values[1][4];
  m_state[3] = values[1][3];  
  m_state[11] = Long.fromNumber(m_state[11] + xmux(m_state[10], m_state[1], m_state[8])).getLowBitsUnsigned();
  m_state[10] = Long.fromNumber(util.rotl(Long.fromNumber(m_state[10]).multiply(Long.fromNumber(0x54655307)).getLowBitsUnsigned(), 7)).getLowBitsUnsigned();  
    
  // Internal state of operation
  this.internalIndex = 0;
  this.internalStepIndex = 0;
  this.outputStep = 0;
  this.outputStepIndex = 0;
  this.step = 0;  
  this.currentValue = 0;
  
  // Initial state of variables
  var s0 = this.m_state[0];
  var s1 = this.m_state[1];
  var s2 = this.m_state[2];
  var s3 = this.m_state[3];
  var s4 = this.m_state[4];
  var s5 = this.m_state[5];
  var s6 = this.m_state[6];
  var s7 = this.m_state[7];
  var s8 = this.m_state[8];
  var s9 = this.m_state[9];
  var reg1 = this.m_state[10];
  var reg2 = this.m_state[11];
  var u0 = 0, u1 = 0, u2 = 0, u3 = 0, u4 = 0, v0 = 0, v1 = 0, v2 = 0, v3 = 0;
  // State variables
  this.outputs = [u0, u1, u2, u3, u4, v0, v1, v2, v3];
  this.results = [];
}

var xmux = function(c, x, y) {
  return Long.fromNumber(x ^ Long.fromNumber(y & (0 - (c & 1)))).getLowBitsUnsigned();
}

var output = function(i, src, u1, u2, u3, u4, v0, v1, v2, v3) {
  var value = util.encodeUInt32R(u2 ^ v0);
  src[i] = src[i] ^ value[0];
  src[i + 1] = src[i + 1] ^ value[1];
  src[i + 2] = src[i + 2] ^ value[2];
  src[i + 3] = src[i + 3] ^ value[3];
  
  value = util.encodeUInt32R(u3 ^ v1);
  src[i + 4] = src[i + 4] ^ value[0];
  src[i + 5] = src[i + 5] ^ value[1];
  src[i + 6] = src[i + 6] ^ value[2];
  src[i + 7] = src[i + 7] ^ value[3];
  
  value = util.encodeUInt32R(u1 ^ v2);
  src[i + 8] = src[i + 8] ^ value[0];
  src[i + 9] = src[i + 9] ^ value[1];
  src[i + 10] = src[i + 10] ^ value[2];
  src[i + 11] = src[i + 11] ^ value[3];
  
  value = util.encodeUInt32R(u4 ^ v3);
  src[i + 12] = src[i + 12] ^ value[0];
  src[i + 13] = src[i + 13] ^ value[1];
  src[i + 14] = src[i + 14] ^ value[2];
  src[i + 15] = src[i + 15] ^ value[3];  
}

Sosemanuk.prototype.returnByte = function(input) {
  var self = this;    

  // Check if we need to adjust the
  if(this.internalIndex % 16 == 0) {
    switch(this.step) {
      case 0:
        step(this.m_state, this.outputs, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 5, 0);
        step(this.m_state, this.outputs, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 6, 1);    
        step(this.m_state, this.outputs, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 7, 2);    
        step(this.m_state, this.outputs, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 8, 3);    
        break;
      case 1:
        step(this.m_state, this.outputs, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 5, 0);    
        step(this.m_state, this.outputs, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 6, 1);    
        step(this.m_state, this.outputs, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 7, 2);    
        step(this.m_state, this.outputs, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 8, 3);          
        break;
      case 2:
        step(this.m_state, this.outputs, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 5, 0);    
        step(this.m_state, this.outputs, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 6, 1);    
        step(this.m_state, this.outputs, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 2);    
        step(this.m_state, this.outputs, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 8, 3);    
        break;
      case 3:
        step(this.m_state, this.outputs, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 5, 0);    
        step(this.m_state, this.outputs, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 6, 1);    
        step(this.m_state, this.outputs, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 7, 2);    
        step(this.m_state, this.outputs, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 8, 3);    
        break;
      case 4:
        step(this.m_state, this.outputs, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 5, 0);    
        step(this.m_state, this.outputs, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 6, 1);    
        step(this.m_state, this.outputs, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 7, 2);    
        step(this.m_state, this.outputs, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 3);    
        break;
    }
    
    // Save serpent encoded
    this.results = Serpent.S2(0, 0, 0, this.outputs[0], this.outputs[1], this.outputs[2], this.outputs[3], this.outputs[4]);
    // Update step location
    this.step = this.step + 1;
    this.step = this.step > 4 ? 0 : this.step;    
    // Update internal step pointer
    this.internalStepIndex = 0;
  }
  
  // Correctly encode the value
  if(this.internalIndex % 4 == 0) {    
    switch(this.outputStep) {
      case 0:
        this.currentValue = util.encodeUInt32R(this.results[2] ^ this.outputs[5]);
        break;        
      case 1:
        this.currentValue = util.encodeUInt32R(this.results[3] ^ this.outputs[6]);
        break;
      case 2:
        this.currentValue = util.encodeUInt32R(this.results[1] ^ this.outputs[7]);
        break;
      case 3:
        this.currentValue = util.encodeUInt32R(this.results[4] ^ this.outputs[8]);
        break;
    }    
    
    // Update step location
    this.outputStep = this.outputStep + 1;
    this.outputStep = this.outputStep > 3 ? 0 : this.outputStep;
    // Update the output step index
    this.outputStepIndex = 0;    
  }

  // Xor value
  input = input ^ this.currentValue[this.outputStepIndex];
  // Update the internal step pointer
  this.internalStepIndex = this.internalStepIndex + 1;
  // Update internal stream pointer
  this.internalIndex = this.internalIndex + 1;
  // Update output step index
  this.outputStepIndex = this.outputStepIndex + 1;
  // Return encrypted byte
  return input;
}

Sosemanuk.prototype.processBytes = function(src, index) {
  index = index == null ? 0 : index;
  
  for(var i = index; i < src.length; i++) {
    src[i] = this.returnByte(src[i]);
  }  
}

// Sosemanuk.prototype.processBytes = function(src, index) {
//   index = index == null ? 0 : index;
//   var self = this;  
//   var s0 = this.m_state[0];
//   var s1 = this.m_state[1];
//   var s2 = this.m_state[2];
//   var s3 = this.m_state[3];
//   var s4 = this.m_state[4];
//   var s5 = this.m_state[5];
//   var s6 = this.m_state[6];
//   var s7 = this.m_state[7];
//   var s8 = this.m_state[8];
//   var s9 = this.m_state[9];
//   var reg1 = this.m_state[10];
//   var reg2 = this.m_state[11];
//   var u0 = 0, u1 = 0, u2 = 0, u3 = 0, u4 = 0, v0 = 0, v1 = 0, v2 = 0, v3 = 0;
//   
//   var variables = [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, reg1, reg2];
//   var outputs = [u0, u1, u2, u3, u4, v0, v1, v2, v3];
//   var i = index;
//   var l = src.length;
//   var values = null;
// 
//   // debug("=================== m_State START")
//   // debug(variables)
//   
//   do {
//     switch(this.step) {
//       case 0:
//         values = step(variables, outputs, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 5, 0);
//         values = step(variables, outputs, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 6, 1);    
//         values = step(variables, outputs, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 7, 2);    
//         values = step(variables, outputs, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 8, 3);    
//         break;
//       case 1:
//         values = step(variables, outputs, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 5, 0);    
//         values = step(variables, outputs, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 6, 1);    
//         values = step(variables, outputs, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 7, 2);    
//         values = step(variables, outputs, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 8, 3);          
//         break;
//       case 2:
//         values = step(variables, outputs, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 5, 0);    
//         values = step(variables, outputs, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 6, 1);    
//         values = step(variables, outputs, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 7, 2);    
//         values = step(variables, outputs, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 8, 3);    
//         break;
//       case 3:
//         values = step(variables, outputs, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 5, 0);    
//         values = step(variables, outputs, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 6, 1);    
//         values = step(variables, outputs, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 7, 2);    
//         values = step(variables, outputs, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 8, 3);    
//         break;
//       case 4:
//         values = step(variables, outputs, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 5, 0);    
//         values = step(variables, outputs, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 6, 1);    
//         values = step(variables, outputs, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 7, 2);    
//         values = step(variables, outputs, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 3);    
//         break;
//     }
// 
//     // debug("=================== m_State")
//     // debug(variables)
//     
//     // 
//     //  OUTPUT
//     var results = Serpent.S2(0, 0, 0, outputs[0], outputs[1], outputs[2], outputs[3], outputs[4]);
//     v0 = outputs[5];
//     v1 = outputs[6];
//     v2 = outputs[7];
//     v3 = outputs[8];
//     u0 = outputs[0] = results[0];
//     u1 = outputs[1] = results[1];
//     u2 = outputs[2] = results[2];
//     u3 = outputs[3] = results[3];
//     u4 = outputs[4] = results[4];
//     output(i, src, u1, u2, u3, u4, v0, v1, v2, v3);
//     i = i + 16;      
//     
//     // Update step location
//     this.step = this.step + 1;
//     this.step = this.step > 4 ? 0 : this.step;
//   } while(i < l)
//   
//   // Update the m_state
//   this.m_state = variables;   
//   
//   // debug("=================== m_State")
//   // debug(this.m_state)
//    
//   // If we have 
//   if((i - l) > 0) {
//     return src.slice(0, l);
//   }   
//   return src;
// }

var r1 = function(i , reg1, reg2) {
  return (i % 2) ? reg2 : reg1;  
}

var r2 = function(i, reg1, reg2) {
  return (i % 2) ? reg1 : reg2;
}

var mula = function(x) {
  return Long.fromNumber(util.rotl(x, 8) ^ s_sosemanukMulTables[((x >> 24) & 0xff)]).getLowBitsUnsigned();
}

var diva = function(x) {
  var r = Long.fromNumber((x >>> 8) ^ s_sosemanukMulTables[256 + (x & 0xff)]).getLowBitsUnsigned();
  return r;
}

// Freaking terrible code urg but closest to the weird jumps done by the c code
var step = function(variables, outputs, x0index, x1index, x2index, x3index, x4index, x5index, x6index, x7index, x8index, x9index, vindex, uindex) {
  outputs[uindex] = Long.fromNumber(Long.fromNumber(variables[x9index]).add(Long.fromNumber(r2(x0index, variables[10], variables[11]))).getLowBitsUnsigned() ^ r1(x0index, variables[10], variables[11])).getLowBitsUnsigned();
  outputs[vindex] = variables[x0index];
  variables[x0index] = Long.fromNumber(mula(variables[x0index]) ^ diva(variables[x3index]) ^ variables[x9index]).getLowBitsUnsigned();
  
  if(x0index % 2) {
    variables[11] = Long.fromNumber(variables[11]).add(Long.fromNumber(xmux(r2(x0index, variables[10], variables[11]), variables[x2index], variables[x9index]))).getLowBitsUnsigned();
  } else {
    variables[10] = Long.fromNumber(variables[10]).add(Long.fromNumber(xmux(r2(x0index, variables[10], variables[11]), variables[x2index], variables[x9index]))).getLowBitsUnsigned();
  }

  if(x0index % 2) {
    variables[10] = Long.fromNumber(util.rotl(Long.fromNumber(r2(x0index, variables[10], variables[11])).multiply(Long.fromNumber(0x54655307)).getLowBitsUnsigned(), 7)).getLowBitsUnsigned();
  } else {
    variables[11] = Long.fromNumber(util.rotl(Long.fromNumber(r2(x0index, variables[10], variables[11])).multiply(Long.fromNumber(0x54655307)).getLowBitsUnsigned(), 7)).getLowBitsUnsigned();
  }
}

var s_sosemanukMulTables = [
  0x00000000, 0xE19FCF12, 0x6B973724, 0x8A08F836, 
  0xD6876E48, 0x3718A15A, 0xBD10596C, 0x5C8F967E, 
  0x05A7DC90, 0xE4381382, 0x6E30EBB4, 0x8FAF24A6, 
  0xD320B2D8, 0x32BF7DCA, 0xB8B785FC, 0x59284AEE, 
  0x0AE71189, 0xEB78DE9B, 0x617026AD, 0x80EFE9BF, 
  0xDC607FC1, 0x3DFFB0D3, 0xB7F748E5, 0x566887F7, 
  0x0F40CD19, 0xEEDF020B, 0x64D7FA3D, 0x8548352F, 
  0xD9C7A351, 0x38586C43, 0xB2509475, 0x53CF5B67, 
  0x146722BB, 0xF5F8EDA9, 0x7FF0159F, 0x9E6FDA8D, 
  0xC2E04CF3, 0x237F83E1, 0xA9777BD7, 0x48E8B4C5, 
  0x11C0FE2B, 0xF05F3139, 0x7A57C90F, 0x9BC8061D, 
  0xC7479063, 0x26D85F71, 0xACD0A747, 0x4D4F6855, 
  0x1E803332, 0xFF1FFC20, 0x75170416, 0x9488CB04, 
  0xC8075D7A, 0x29989268, 0xA3906A5E, 0x420FA54C, 
  0x1B27EFA2, 0xFAB820B0, 0x70B0D886, 0x912F1794, 
  0xCDA081EA, 0x2C3F4EF8, 0xA637B6CE, 0x47A879DC, 
  0x28CE44DF, 0xC9518BCD, 0x435973FB, 0xA2C6BCE9, 
  0xFE492A97, 0x1FD6E585, 0x95DE1DB3, 0x7441D2A1, 
  0x2D69984F, 0xCCF6575D, 0x46FEAF6B, 0xA7616079, 
  0xFBEEF607, 0x1A713915, 0x9079C123, 0x71E60E31, 
  0x22295556, 0xC3B69A44, 0x49BE6272, 0xA821AD60, 
  0xF4AE3B1E, 0x1531F40C, 0x9F390C3A, 0x7EA6C328, 
  0x278E89C6, 0xC61146D4, 0x4C19BEE2, 0xAD8671F0, 
  0xF109E78E, 0x1096289C, 0x9A9ED0AA, 0x7B011FB8, 
  0x3CA96664, 0xDD36A976, 0x573E5140, 0xB6A19E52, 
  0xEA2E082C, 0x0BB1C73E, 0x81B93F08, 0x6026F01A, 
  0x390EBAF4, 0xD89175E6, 0x52998DD0, 0xB30642C2, 
  0xEF89D4BC, 0x0E161BAE, 0x841EE398, 0x65812C8A, 
  0x364E77ED, 0xD7D1B8FF, 0x5DD940C9, 0xBC468FDB, 
  0xE0C919A5, 0x0156D6B7, 0x8B5E2E81, 0x6AC1E193, 
  0x33E9AB7D, 0xD276646F, 0x587E9C59, 0xB9E1534B, 
  0xE56EC535, 0x04F10A27, 0x8EF9F211, 0x6F663D03, 
  0x50358817, 0xB1AA4705, 0x3BA2BF33, 0xDA3D7021, 
  0x86B2E65F, 0x672D294D, 0xED25D17B, 0x0CBA1E69, 
  0x55925487, 0xB40D9B95, 0x3E0563A3, 0xDF9AACB1, 
  0x83153ACF, 0x628AF5DD, 0xE8820DEB, 0x091DC2F9, 
  0x5AD2999E, 0xBB4D568C, 0x3145AEBA, 0xD0DA61A8, 
  0x8C55F7D6, 0x6DCA38C4, 0xE7C2C0F2, 0x065D0FE0, 
  0x5F75450E, 0xBEEA8A1C, 0x34E2722A, 0xD57DBD38, 
  0x89F22B46, 0x686DE454, 0xE2651C62, 0x03FAD370, 
  0x4452AAAC, 0xA5CD65BE, 0x2FC59D88, 0xCE5A529A, 
  0x92D5C4E4, 0x734A0BF6, 0xF942F3C0, 0x18DD3CD2, 
  0x41F5763C, 0xA06AB92E, 0x2A624118, 0xCBFD8E0A, 
  0x97721874, 0x76EDD766, 0xFCE52F50, 0x1D7AE042, 
  0x4EB5BB25, 0xAF2A7437, 0x25228C01, 0xC4BD4313, 
  0x9832D56D, 0x79AD1A7F, 0xF3A5E249, 0x123A2D5B, 
  0x4B1267B5, 0xAA8DA8A7, 0x20855091, 0xC11A9F83, 
  0x9D9509FD, 0x7C0AC6EF, 0xF6023ED9, 0x179DF1CB, 
  0x78FBCCC8, 0x996403DA, 0x136CFBEC, 0xF2F334FE, 
  0xAE7CA280, 0x4FE36D92, 0xC5EB95A4, 0x24745AB6, 
  0x7D5C1058, 0x9CC3DF4A, 0x16CB277C, 0xF754E86E, 
  0xABDB7E10, 0x4A44B102, 0xC04C4934, 0x21D38626, 
  0x721CDD41, 0x93831253, 0x198BEA65, 0xF8142577, 
  0xA49BB309, 0x45047C1B, 0xCF0C842D, 0x2E934B3F, 
  0x77BB01D1, 0x9624CEC3, 0x1C2C36F5, 0xFDB3F9E7, 
  0xA13C6F99, 0x40A3A08B, 0xCAAB58BD, 0x2B3497AF, 
  0x6C9CEE73, 0x8D032161, 0x070BD957, 0xE6941645, 
  0xBA1B803B, 0x5B844F29, 0xD18CB71F, 0x3013780D, 
  0x693B32E3, 0x88A4FDF1, 0x02AC05C7, 0xE333CAD5, 
  0xBFBC5CAB, 0x5E2393B9, 0xD42B6B8F, 0x35B4A49D, 
  0x667BFFFA, 0x87E430E8, 0x0DECC8DE, 0xEC7307CC, 
  0xB0FC91B2, 0x51635EA0, 0xDB6BA696, 0x3AF46984, 
  0x63DC236A, 0x8243EC78, 0x084B144E, 0xE9D4DB5C, 
  0xB55B4D22, 0x54C48230, 0xDECC7A06, 0x3F53B514,

	0x00000000, 0x180F40CD, 0x301E8033, 0x2811C0FE,
	0x603CA966, 0x7833E9AB, 0x50222955, 0x482D6998,
	0xC078FBCC, 0xD877BB01, 0xF0667BFF, 0xE8693B32,
	0xA04452AA, 0xB84B1267, 0x905AD299, 0x88559254,
	0x29F05F31, 0x31FF1FFC, 0x19EEDF02, 0x01E19FCF,
	0x49CCF657, 0x51C3B69A, 0x79D27664, 0x61DD36A9,
	0xE988A4FD, 0xF187E430, 0xD99624CE, 0xC1996403,
	0x89B40D9B, 0x91BB4D56, 0xB9AA8DA8, 0xA1A5CD65,
	0x5249BE62, 0x4A46FEAF, 0x62573E51, 0x7A587E9C,
	0x32751704, 0x2A7A57C9, 0x026B9737, 0x1A64D7FA,
	0x923145AE, 0x8A3E0563, 0xA22FC59D, 0xBA208550,
	0xF20DECC8, 0xEA02AC05, 0xC2136CFB, 0xDA1C2C36,
	0x7BB9E153, 0x63B6A19E, 0x4BA76160, 0x53A821AD,
	0x1B854835, 0x038A08F8, 0x2B9BC806, 0x339488CB,
	0xBBC11A9F, 0xA3CE5A52, 0x8BDF9AAC, 0x93D0DA61,
	0xDBFDB3F9, 0xC3F2F334, 0xEBE333CA, 0xF3EC7307,
	0xA492D5C4, 0xBC9D9509, 0x948C55F7, 0x8C83153A,
	0xC4AE7CA2, 0xDCA13C6F, 0xF4B0FC91, 0xECBFBC5C,
	0x64EA2E08, 0x7CE56EC5, 0x54F4AE3B, 0x4CFBEEF6,
	0x04D6876E, 0x1CD9C7A3, 0x34C8075D, 0x2CC74790,
	0x8D628AF5, 0x956DCA38, 0xBD7C0AC6, 0xA5734A0B,
	0xED5E2393, 0xF551635E, 0xDD40A3A0, 0xC54FE36D,
	0x4D1A7139, 0x551531F4, 0x7D04F10A, 0x650BB1C7,
	0x2D26D85F, 0x35299892, 0x1D38586C, 0x053718A1,
	0xF6DB6BA6, 0xEED42B6B, 0xC6C5EB95, 0xDECAAB58,
	0x96E7C2C0, 0x8EE8820D, 0xA6F942F3, 0xBEF6023E,
	0x36A3906A, 0x2EACD0A7, 0x06BD1059, 0x1EB25094,
	0x569F390C, 0x4E9079C1, 0x6681B93F, 0x7E8EF9F2,
	0xDF2B3497, 0xC724745A, 0xEF35B4A4, 0xF73AF469,
	0xBF179DF1, 0xA718DD3C, 0x8F091DC2, 0x97065D0F,
	0x1F53CF5B, 0x075C8F96, 0x2F4D4F68, 0x37420FA5,
	0x7F6F663D, 0x676026F0, 0x4F71E60E, 0x577EA6C3,
	0xE18D0321, 0xF98243EC, 0xD1938312, 0xC99CC3DF,
	0x81B1AA47, 0x99BEEA8A, 0xB1AF2A74, 0xA9A06AB9,
	0x21F5F8ED, 0x39FAB820, 0x11EB78DE, 0x09E43813,
	0x41C9518B, 0x59C61146, 0x71D7D1B8, 0x69D89175,
	0xC87D5C10, 0xD0721CDD, 0xF863DC23, 0xE06C9CEE,
	0xA841F576, 0xB04EB5BB, 0x985F7545, 0x80503588,
	0x0805A7DC, 0x100AE711, 0x381B27EF, 0x20146722,
	0x68390EBA, 0x70364E77, 0x58278E89, 0x4028CE44,
	0xB3C4BD43, 0xABCBFD8E, 0x83DA3D70, 0x9BD57DBD,
	0xD3F81425, 0xCBF754E8, 0xE3E69416, 0xFBE9D4DB,
	0x73BC468F, 0x6BB30642, 0x43A2C6BC, 0x5BAD8671,
	0x1380EFE9, 0x0B8FAF24, 0x239E6FDA, 0x3B912F17,
	0x9A34E272, 0x823BA2BF, 0xAA2A6241, 0xB225228C,
	0xFA084B14, 0xE2070BD9, 0xCA16CB27, 0xD2198BEA,
	0x5A4C19BE, 0x42435973, 0x6A52998D, 0x725DD940,
	0x3A70B0D8, 0x227FF015, 0x0A6E30EB, 0x12617026,
	0x451FD6E5, 0x5D109628, 0x750156D6, 0x6D0E161B,
	0x25237F83, 0x3D2C3F4E, 0x153DFFB0, 0x0D32BF7D,
	0x85672D29, 0x9D686DE4, 0xB579AD1A, 0xAD76EDD7,
	0xE55B844F, 0xFD54C482, 0xD545047C, 0xCD4A44B1,
	0x6CEF89D4, 0x74E0C919, 0x5CF109E7, 0x44FE492A,
	0x0CD320B2, 0x14DC607F, 0x3CCDA081, 0x24C2E04C,
	0xAC977218, 0xB49832D5, 0x9C89F22B, 0x8486B2E6,
	0xCCABDB7E, 0xD4A49BB3, 0xFCB55B4D, 0xE4BA1B80,
	0x17566887, 0x0F59284A, 0x2748E8B4, 0x3F47A879,
	0x776AC1E1, 0x6F65812C, 0x477441D2, 0x5F7B011F,
	0xD72E934B, 0xCF21D386, 0xE7301378, 0xFF3F53B5,
	0xB7123A2D, 0xAF1D7AE0, 0x870CBA1E, 0x9F03FAD3,
	0x3EA637B6, 0x26A9777B, 0x0EB8B785, 0x16B7F748,
	0x5E9A9ED0, 0x4695DE1D, 0x6E841EE3, 0x768B5E2E,
	0xFEDECC7A, 0xE6D18CB7, 0xCEC04C49, 0xD6CF0C84,
	0x9EE2651C, 0x86ED25D1, 0xAEFCE52F, 0xB6F3A5E2
]
