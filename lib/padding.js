var NullPad = exports.NullPad = function() {}

NullPad.prototype.unpad = function(a) {
  return a;
}

NullPad.prototype.pad = function(a) {
  return a;
}

NullPad.prototype.setBlockSize = function(bs) {
  return bs;
}