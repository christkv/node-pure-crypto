var Random = require('../prng/random').Random,
  utils = require('../utils'),
  debug = require('util').debug,
  inspect = require('util').inspect;

var HEADER_LENGTH = 10;

var PKCS1 = exports.PKCS1 = function(engine) {
  this.engine = engine;
}

PKCS1.prototype.getUnderlyingCipher = function() {
  return this.engine;
}

PKCS1.prototype.init = function(forEncryption, param) {
  this.random = new Random();
  this.engine.init(forEncryption, param);
  this.forPrivateKey = param.isPrivate();
  this.forEncryption = forEncryption;
}

PKCS1.prototype.getInputBlockSize = function() {
  var baseBlockSize = this.engine.getInputBlockSize();
  if(this.forEncryption) {
    return baseBlockSize - HEADER_LENGTH;
  } else {
    return baseBlockSize;
  }
}

PKCS1.prototype.getOutputBlockSize = function() {
  var baseBlockSize = this.engine.getOutputBlockSize();
  if(this.forEncryption) {
    return baseBlockSize;
  } else {
    return baseBlockSize - HEADER_LENGTH;
  }  
}

PKCS1.prototype.processBlock = function(input, inOff, inLen) {
  if(this.forEncryption) {
    return encodeBlock(this, input, inOff, inLen);
  } else {
    return decodeBlock(this, input, inOff, inLen);
  }
}

var encodeBlock = function(self, input, inOff, inLen) {
  if(inLen > self.getInputBlockSize()) throw new Error("input data too large");
  
  var block = new Array(self.engine.getInputBlockSize());
  if(self.forPrivateKey) {    
    // type code 1
    block[0] = 0x01;    

    for(var i = 0; i != block.length - inLen - 1; i++) {
      block[i] = 0xff;
    }
  } else {
    self.random.nextBytes(block);
    // type code 2
    block[0] = 0x02;
    
    //
    // a zero byte marks the end of the padding, so all
    // the pad bytes must be non-zero.
    //
    for (var i = 1; i != block.length - inLen - 1; i++) {
      while (block[i] == 0) {
        // block[i] = self.random.nextByte();
        block[i] = 1;
      }
    }
    
    block[block.length - inLen - 1] = 0x00;
    utils.copy(block, block.length - inLen, input, inOff, inLen);
    return self.engine.processBlock(block, 0, block.length);
  }
}

var decodeBlock = function(self, input, inOff, inLen) {
  var block = self.engine.processBlock(input, inOff, inLen);
  
  if(block.length < self.getOutputBlockSize()) throw new Error("block truncated");
  
  var type = block[0];
  
  if(type != 1 && type != 2) throw new Error("unknown block type");
  if(block.length != self.engine.getOutputBlockSize()) throw new Error("block incorrect size");

  var start = 0;
  
  for(start = 1; start != block.length; start++) {
    var pad = block[start];
    
    if(pad == 0) {
      break;
    } 
    
    if(type == 1 && pad != 0xff) throw new Error("block padding incorrect");
  }
  
  start = start + 1;
  
  if(start > block.length || start < HEADER_LENGTH) throw new Error("no data in block");

  // Return the block minus padding
  return block.slice(start);
}


















