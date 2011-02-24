var debug = require('sys').debug,
  inspect = require('sys').inspect,
  util = require('utils'),
  inherits = require('sys').inherits,
  DESKey = require('des').DESKey;

/**
 * This supports 2TDES and 3TDES.
 * If the key passed is 128 bits, 2TDES is used.
 * If the key has 192 bits, 3TDES is used.
 * Other key lengths give "undefined" results.
 */
var TripleDESKey = exports.TripleDESKey = function(key) {
  this.key = key;
  this.encKey = this.generateWorkingKey(true, key, 0);
  this.decKey = this.generateWorkingKey(false, key, 0);

  // Encoding variables
  this.encKey2 = this.generateWorkingKey(false, key, 8);
  this.decKey2 = this.generateWorkingKey(true, key, 8);
  
  if(key.length > 16) {
    this.encKey3 = this.generateWorkingKey(true, key, 16);
    this.decKey3 = this.generateWorkingKey(false, key, 16);
  } else {
    this.encKey3 = encKey;
    this.decKey3 = decKey;
  }
}

inherits(TripleDESKey, DESKey);

TripleDESKey.prototype.encrypt = function(block, index) {
  
  
  index = index == null ? 0 : index;
  var encrypted = this.desFunc(this.encKey, block, index);
  encrypted = this.desFunc(this.encKey2, encrypted, 0);
  return this.desFunc(this.encKey3, encrypted, 0);
}

TripleDESKey.prototype.decrypt = function(block, index) {
  index = index == null ? 0 : index;
  var decrypted = this.desFunc(this.decKey3, block, index);
  decrypted = this.desFunc(this.decKey2, decrypted, 0);
  return this.desFunc(this.decKey, decrypted, 0);
}
