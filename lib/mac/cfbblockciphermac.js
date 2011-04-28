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

const BLOCK_SIZE = 8;

var CFBBlockCipherMac = exports.CFBBlockCipherMac = function(cipher, bitBlockSize, iv) {
  this.cipher = cipher;
  this.blockSize = bitBlockSize;
  
  this.iv = zeroedArray(cipher.getBlockSize());
  this.cfbV = zeroedArray(cipher.getBlockSize());
  this.cfbOutV = zeroedArray(cipher.getBlockSize());
  
  if(iv != null) {
    if(iv.length < this.iv.length) {
      util.copy(this.iv, (this.iv.length - iv.length), iv, 0, iv.length);
    } else {
      this.iv = iv.slice(0);
    }    
    
    this.reset();
  }
}

CFBBlockCipherMac.prototype.getBlockSize = function() {
  return BLOCK_SIZE;
}

CFBBlockCipherMac.prototype.reset = function() {
  this.cfbV = this.iv.slice(0);
}
