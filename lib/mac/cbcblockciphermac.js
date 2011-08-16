var CBC = require('symmetric/modes/cbc').CBC,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils');

var longZeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = Long.ZERO;
  return a;
}

var zeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = 0;
  return a;
}

var CBCBlockCipherMac = exports.CBCBlockCipherMac = function(cipher, macSizeInBits, padding) {
  // Initialize only if we have a cipher
  if(cipher != null) {    
    if(macSizeInBits == null) {
      macSizeInBits = (cipher.getBlockSize() * 8) / 2;
      this.macSize = (macSizeInBits) / 8;
    } else {
      this.macSize = macSizeInBits / 8;      
    }

    // Checks
    if((macSizeInBits % 8) != 0) {
      throw "MAC size must be multiple of 8";
    }

    // Set up CBC cipher
    this.cipher = new CBC(cipher);
    this.padding = padding;
    this.mac = zeroedArray(cipher.getBlockSize());
    this.buf = zeroedArray(cipher.getBlockSize());
    this.bufOff = 0;
  }
}

CBCBlockCipherMac.prototype.getAlgorithmName = function() {
  return this.cipher.getAlgorithmName();
}

CBCBlockCipherMac.prototype.init = function(iv, key) {  
  // Get all the arguments
  var args = Array.prototype.slice.call(arguments, 0);
  // Reset the cipher
  this.reset();
  // Get rid of iv if not specified or set to null
  if(iv == null) args.shift();
  // Append the arguments to the cipher initializer
  this.cipher.init.apply(this.cipher, [true, iv == null ? false : true].concat(args));
}

CBCBlockCipherMac.prototype.getMacSize = function() {
  return this.macSize;
}

CBCBlockCipherMac.prototype.update = function() {
  // Get all the arguments
  var args = Array.prototype.slice.call(arguments, 0);  
  
  if(args.length == 1 && !Array.isArray(args[0])) {
    var input = args.shift() & 255;
    
    if(this.bufOff == this.buf.length) {      
      this.cipher.processBlock(this.buf, 0, this.mac, 0);
      this.bufOff = 0;
    }
    this.buf[this.bufOff++] = input;
  } else if(args.length > 0 && Array.isArray(args[0])) {
    var src = args.length ? args.shift() : null; 
    var inOff = args.length ? args.shift() : 0;
    // If we have a negative length throw an error
    if(src.length < 0) throw "Can't have a negative input length!";
    var len = args.length ? args.shift() : src.length;
    // Length of input
    var blockSize = this.cipher.getBlockSize();
    var gapLen = blockSize - this.bufOff;
        
    if(len > gapLen) {
      util.copy(this.buf, this.bufOff, src, inOff, gapLen);
      this.cipher.processBlock(this.buf, 0, this.mac, 0);
      this.bufOff = 0;
      len = len - gapLen;
      inOff = inOff + gapLen;
      
      while(len > blockSize) {
        this.cipher.processBlock(src, inOff, this.mac, 0);
        len = len - blockSize;
        inOff = inOff + blockSize;
      }    
    }  
    
    util.copy(this.buf, this.bufOff, src, inOff, len);
    this.bufOff = this.bufOff + len;
  } else {
    throw "Not a legal set of parameters";
  }
}

CBCBlockCipherMac.prototype.doFinal = function(out, outOff) {
  outOff = outOff == null ? 0 : outOff;
  var blockSize = this.cipher.getBlockSize();

  if(this.padding == null) {
    // Pad with zeros
    while(this.bufOff < blockSize) {
      this.buf[this.bufOff] = 0;
      this.bufOff++;
    }
  } else {
    if(this.bufOff == blockSize) {
      // this.mac = this.cipher.processBlock(true, this.buf, 0, this.mac, 0, this.buf.length);
      this.mac = this.buf.slice(0);
      this.cipher.processBlock(this.mac, 0, this.mac, 0);
      this.bufOff = 0;
    }
    
    this.buf = this.padding.pad(this.buf, this.bufOff);
  }
  
  // this.mac = this.cipher.processBlock(true, this.buf, 0, this.mac, 0, this.buf.length);
  this.mac = this.buf.slice(0);
  this.cipher.processBlock(this.mac, 0, this.mac, 0);  
  
  for(var i = 0; i < this.macSize; i++) {
    out[outOff + i] = this.mac[i];
  }

  this.reset();
  return this.macSize;
}

CBCBlockCipherMac.prototype.reset = function() {
  // clean the buffer.
  for (var i = 0; i < this.buf.length; i++) {
    this.buf[i] = 0;
  }

  this.bufOff = 0;
  // reset the underlying cipher.
  this.cipher.reset();
}



