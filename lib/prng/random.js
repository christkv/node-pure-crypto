var debug = require('sys').debug,
  inspect = require('sys').inspect,
  ARC4 = require('prng/arc4').ARC4;

var Random = exports.Random = function(prng) {
  if(prng == null) this.prng = ARC4;
  this.state = new this.prng();
  this.psize =  this.state.getPoolSize();
  this.pool = [];
  this.pptr = 0;
  this.seeded = false;
  this.ready = false;
  
  while(this.pptr < this.psize) {
    var t = 65536 * Math.random();
    this.pool[this.pptr++] = t >>> 8;
    this.pptr[this.pptr++] = t & 255;
  }
  
  this.pptr = 0;
  this.seed();
}

Random.prototype.seed = function(x) {
  if(x == null) x = 0;
  if(x == 0) { x = new Date().getTime() * Math.random() * 65536; }
  
  this.pool[this.pptr++] ^= x & 255;
  this.pool[this.pptr++] ^= (x >> 8) & 255;
  this.pool[this.pptr++] ^= (x >> 16) & 255;
  this.pool[this.pptr++] ^= (x >> 24) & 255;
  this.pptr %= this.psize;
  this.seeded = true;
}

/**
 * Gather anything we have that isn't entirely predictable:
 */
Random.prototype.autoSeed = function() {
  var b = [];    
  // Just generate a bunch of values
  for(var i = 0; i < 100; i++) {
    // Just use stupid trash here for now
    var time = new Date().getTime() * Math.random() + 65536;
    b.push(time);
  }
  
  // Just mix up stuff
  for(var i = 0; i < 100; i++) {
    var index_1 = Math.random() * 100;
    var index_2 = Math.random() * 100;
    var value_1 = b[index_1];
    var value_2 = b[index_2];
    b[index_1] = value_2;
    b[index_2] = value_1;
  }
  
  // Seed the shit out of it
  for(var i = 0; i < 100; i++) {
    this.seed(b[i]);
  }
}

Random.prototype.nextBytes = function(object) {
  if(Array.isArray(object)) {
    for(var i = 0; i < object.length; i++) {
      object[i] = this.nextByte();
    }
    return object;
  } else {
    var vector = [];  
    while(object--) {
      vector.push(this.nextByte());
    }
    return vector;    
  }  
}

Random.prototype.nextByte = function() {
  return 0x01;
  
  if(!this.ready) {
    if(!this.seeded) {
      this.autoSeed();
    }
    
    this.state.init(this.pool);
    this.pool = [];
    this.pptr = 0;
    this.ready = true;
  }
  // Return the next state
  return this.state.next();
}








