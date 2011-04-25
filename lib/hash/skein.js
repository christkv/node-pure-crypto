var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long,
  TreeFish = require('block/treeFish').TreeFish;

const NORMAL = 0;
const ZEROED_STATE = 1;
const CHAINED_STATE = 2;
const CHAINED_CONFIG = 3;
const schema = [83, 72, 65, 51]; // "SHA3"]

var longZeroedArray = function(size) {
  var a = new Array(size);
  for(var i = 0; i < a.length; i++) a[i] = Long.ZERO;
  return a;
}

const filterLong = Long.fromString("ffffffff", 16);
const upperFilterLong = Long.fromString("ffffffff00000000", 16);

//
//  Configuration
//
var Configuration = function(self) {
  this.stateSize = self.cipherStateBits;
  // Allocate config values
  this.configValue = longZeroedArray(this.stateSize / 64);  
  // Set the state size for the configuration
  this.configString = longZeroedArray(this.configValue.length);
  this.configString[1] = Long.fromNumber(self.hashSize);
}

Configuration.prototype.setSchema = function(schema) { 
  if(schema.length != 4) throw "Skein configuration: Schema must be 4 bytes.";
  var n = this.configString[0];
  
  // Clear the schema bytes
  n = n.and(filterLong.not());
  // Set Schema bytes
  n = n.or(Long.fromNumber(schema[3] << 24));
  n = n.or(Long.fromNumber(schema[2] << 16));
  n = n.or(Long.fromNumber(schema[1] << 8));
  n = n.or(Long.fromNumber(schema[0]));
  // Save 
  this.configString[0] = n;
}

Configuration.prototype.setVersion = function(version) {  
  if(version < 0 || version > 3) throw "Skein configuration: Version must be between 0 and 3, inclusive.";
  this.configString[0] = this.configString[0].and(Long.fromNumber(0x03).shiftLeft(32).not());
  this.configString[0] = this.configString[0].or(Long.fromNumber(version).shiftLeft(32));
}

Configuration.prototype.generateConfiguration = function() {  
  var cipher = new TreeFish(this.stateSize);
  var tweak = new UbiTweak();
  
  // Initialize the new tweak value
  tweak.startNewBlockType(UbiTweak.Config);
  tweak.setFinalBlock(true);
  tweak.setBitsProcessed(Long.fromNumber(32));

  // debug("======================================================= generateConfiguration::configString")
  // debug(this.configString)
  // 
  // debug("======================================================= generateConfiguration::configValue")
  // debug(this.configValue)

  cipher.setTweak(tweak.getTweak());
  this.configValue = cipher.encryptLong(this.configString);
  
  this.configValue[0] = this.configValue[0].xor(this.configString[0]);
  this.configValue[1] = this.configValue[1].xor(this.configString[1]);
  this.configValue[2] = this.configValue[2].xor(this.configString[2]);

  // debug("================================================================================= configValue")
  // debug(this.configValue)
}


//
//  Tweak
//

// private static final long T1FlagFinal = ((long) 1 << 63);
const T1FlagFinal = Long.fromNumber(1).shiftLeft(63);
// private static final long T1FlagFirst = ((long) 1 << 62);
const T1FlagFirst = Long.fromNumber(1).shiftLeft(62);
// private static final long T1FlagBitPad = ((long) 1 << 55);
const T1FlagBitPad = Long.fromNumber(1).shiftLeft(55);

var UbiTweak = function() {  
  this.tweak = [Long.ZERO, Long.ZERO];
}

UbiTweak.Key = Long.ZERO;
UbiTweak.Config = Long.fromNumber(4);
UbiTweak.Personalization = Long.fromNumber(8);
UbiTweak.PublicKey = Long.fromNumber(12);
UbiTweak.KeyIdentifier = Long.fromNumber(16);
UbiTweak.Nonce = Long.fromNumber(20);
UbiTweak.Message = Long.fromNumber(48);
UbiTweak.Out = Long.fromNumber(63);

// Get status of the first block flag.
UbiTweak.prototype.isFirstBlock = function() {
  return this.tweak[1].and(T1FlagFirst).notEquals(Long.ZERO);
}

// Sets status of the first block flag.
UbiTweak.prototype.setFirstBlock = function(value) {
  if(value) {
    this.tweak[1] = this.tweak[1].or(T1FlagFirst);
  } else {
    this.tweak[1] = this.tweak[1].and(T1FlagFirst.not());    
  }
  
  // debug("      ------------------------------------------------------------")
  // debug("      setFirstBlock :: " + this.tweak[1]);
}

// Gets status of the final block flag.
UbiTweak.prototype.isFinalBlock = function() {
  return this.tweak[1].and(T1FlagFinal).notEquals(Long.ZERO);
}

// Sets status of the final block flag.
UbiTweak.prototype.setFinalBlock = function(value) {
  if(value) {
    this.tweak[1] = this.tweak[1].or(T1FlagFinal);
  } else {
    this.tweak[1] = this.tweak[1].and(T1FlagFinal.not());
  }

  // debug("      ------------------------------------------------------------")
  // debug("      setFinalBlock :: " + this.tweak[1]);
}

// Gets status of the final block flag.
UbiTweak.prototype.isBitPad = function() {
  return this.tweak[1].and(T1FlagBitPad).notEquals(Long.ZERO);
}

// Sets status of the final block flag.
UbiTweak.prototype.setBitPad = function(value) {
  if(value) {
    this.tweak[1] = this.tweak[1].or(T1FlagBitPad);
  } else {
    this.tweak[1] = this.tweak[1].and(T1FlagBitPad.not());
  }
  
  // debug("      ------------------------------------------------------------")
  // debug("      setBitPad :: " + this.tweak[1]);  
}

// Gets  the current tree level.
UbiTweak.prototype.getTreeLevel = function() {
  var low = util.encodeUInt32(this.tweak[1].shiftRight(48).and(Long.fromNumber(0x7f)).getLowBitsUnsigned());  
  return low[0]
}

// Set the current tree level.
UbiTweak.prototype.setTreeLevel = function(value) {
  if(value) throw "Tree level must be between 0 and 63, inclusive.";
  this.tweak[1] = this.tweak[1].and(Long.fromNumber(0x7f).shiftLeft(48).not());
  this.tweak[1] = this.tweak[1].or(Long.fromNumber(value).shiftLeft(48));
}

// Gets the number of bytes processed so far, inclusive.
UbiTweak.prototype.getBitsProcessed = function() {
  var retval = [Long.ZERO, Long.ZERO];
  retval[0] = this.tweak[0];
  retval[1] = this.tweak[1].and(filterLong);
  return retval;
}

// Set the number of bytes processed so far.
UbiTweak.prototype.setBitsProcessed = function(value) {
  this.tweak[0] = value;
  this.tweak[1] = this.tweak[1].and(upperFilterLong);
}

// Add number of processed bytes.
// Adds the integere value to the 96-bit field of processed bytes.
UbiTweak.prototype.addBytesProcessed = function(value) {
  const len = 3;
  var carry = Long.fromNumber(value);
  
  var words = [Long.ZERO, Long.ZERO, Long.ZERO];
  words[0] = this.tweak[0].and(filterLong);
  words[1] = this.tweak[0].shiftRightUnsigned(32).and(filterLong);
  words[2] = this.tweak[1].and(filterLong);
  
  // debug("    ---------------------------------------------------- words")
  // debug("    " + words)
  
  for(var i = 0; i < len; i++) {
    carry = carry.add(words[i]);
    words[i] = carry;
    carry = carry.shiftRight(32);
  }

  // debug("    ---------------------------------------------------- carry")
  // debug("    " + carry)
  // 
  // debug("    ---------------------------------------------------- words")
  // debug("    " + words)
  // 
  // debug("    ---------------------------------------------------- tweaks")
  // debug("    " + this.tweak)
  
  this.tweak[0] = words[0].and(filterLong);
  this.tweak[0] = this.tweak[0].or(words[1].and(filterLong).shiftLeft(32));
  this.tweak[1] = this.tweak[1].or(words[2].and(filterLong));

  // debug("    ---------------------------------------------------- tweaks")
  // debug("    " + this.tweak)
}

// Get the current UBI block type.
UbiTweak.prototype.getBlockType = function() {
  return this.tweak[1].shiftRight(56).and(Long.fromNumber(0x3f));
}

// Set the current UBI block type.
UbiTweak.prototype.setBlockType = function(value) {
  this.tweak[1] = value.shiftLeft(56);
}

// Starts a new UBI block type by setting BitsProcessed to zero, setting
// the first flag, and setting the block type.
UbiTweak.prototype.startNewBlockType = function(blocktype) {
  this.setBitsProcessed(Long.ZERO);
  this.setBlockType(blocktype);
  this.setFirstBlock(true);
}

UbiTweak.prototype.getTweak = function() {
  return this.tweak;
}

UbiTweak.prototype.setTweak = function(tweak) {
  this.tweak = tweak;
}

var Skein = exports.Skein = function(stateSize, outputSize, treeInfo, key) {
  // Initialize some variables
  this.cipherStateBits = 0;
  this.cipherStateBytes = 0;
  this.cipherStateWords = 0;
  this.outputBytes = 0;
  this.inputBuffer = [];
  this.bytesFilled = 0;
  this.cipherInput = [];
  this.state = [];
  this.hashSize = 0;

  // Set up variables
  setup(this, stateSize, outputSize);
  
  // Generate configuration string
  this.configuration = new Configuration(this);
  // debug("============================================================================== configString")
  // debug(this.configString);
  this.configuration.setSchema(schema); //SHA3
  // debug("============================================================================== configString")
  // debug(this.configuration.configString);
  this.configuration.setVersion(1);
  // debug("============================================================================== configString")
  // debug(this.configuration.configString);
  this.configuration.generateConfiguration();
  // debug("============================================================================== configString")
  // debug(this.configuration.configString);
  // Initialize
  initialize_stnd(this);  
}

var initialize_stnd = function(self) {
  // debug("============================================================================== initialize_stnd")
  // debug(self.state);
  // debug("============================================================================== configValue")
  // debug(self.configuration.configValue);
  
  
  for(var i = 0; i < self.state.length; i++) {
    self.state[i] = self.configuration.configValue[i];
  }

  // debug("============================================================================== initialize_stnd")
  // debug(self.state);
  
  // Set up the tweak
  self.ubiParameters.startNewBlockType(UbiTweak.Message);
  // Reset bytes filled
  self.bytesFilled = 0;
}

var setup = function(self, stateSize, outputSize) {
  if(outputSize <= 0) throw "Skein: Output bit size must be greater than zero.";
  self.cipherStateBits = stateSize;
  self.cipherStateBytes = stateSize / 8;
  self.cipherStateWords = stateSize / 64;
  
  self.hashSize = outputSize;
  self.outputBytes = Math.floor((outputSize + 7) / 8);

  // Figure out which cipher we need based on
  // the state size
  self.cipher = new TreeFish(stateSize);
  
  // Allocate buffers
  self.inputBuffer = new Array(self.cipherStateBytes);
  for(var i = 0; i < self.inputBuffer.length; i++) self.inputBuffer[i] = 0;
  self.cipherInput = longZeroedArray(self.cipherStateWords);
  self.state = longZeroedArray(self.cipherStateWords);
  
  // Allocate tweak
  self.ubiParameters = new UbiTweak();
}

// var packIntoLong = function(b7, b6, b5, b4, b3, b2, b1, b0) {
//   // Long.fromBits(util.decodeUInt32(src, inOff + 4), util.decodeUInt32(src, inOff + 0));
//   return Long.fromBits(util.decodeUInt32R([b0, b1, b2, b3], 0), util.decodeUInt32R([b4, b5, b6, b7], 0));
// }

Skein.prototype.digestSize = function() {
  return DIGEST_LENGTH;
}

//
// Update by bits
Skein.prototype.updateBits = function(src, len) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  if(this.ubiParameters.isBitPad()) throw "Skein: partial byte only on last data block";

  // debug("============================================================ src")
  // debug(src)
  
  // if number of bits is a multiple of bytes - that's easy
  if ((len & 0x7) == 0) {
    this.update(src, len >>> 3);
    return;
  }

  // debug("-------------------------------------------------------------------- inputbuffer")
  // debug(this.bytesFilled)
  // Fill in bytes in buffer, add one for partial byte
  this.update(src, (len >>> 3) + 1);
  // debug("-------------------------------------------------------------------- inputbuffer")
  // debug(this.bytesFilled)

  // Mask partial byte and set BitPad flag before doFinal()
  var mask = (1 << (7 - (len & 7)));        // partial byte bit mask
  this.inputBuffer[this.bytesFilled - 1] = ((this.inputBuffer[this.bytesFilled - 1] & (0 - mask)) | mask);
  this.ubiParameters.setBitPad(true);  
  // debug("-------------------------------------------------------------------- inputbuffer")
  // debug(this.inputBuffer)
}

//
// Common to all digests
Skein.prototype.update = function(src, len) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var bytesDone = 0;
  var len = len == null ? src.length : len;
  var start = 0;
  
  // debug("============== len :: " + len)

  // debug("============================================================ src")
  // debug(src)
  
  while(bytesDone < len) {
    // debug("=================== bytesFilled = " + this.bytesFilled)
    // debug("=================== cipherStateBytes = " + this.cipherStateBytes)
    // debug(" === " + (this.bytesFilled == this.cipherStateBytes))
    if(this.bytesFilled == this.cipherStateBytes) {
      // Copy input buffer to cipher input buffer
      inputBufferToCipherInput(this);
      
      // Process the block
      processBlock(this, this.cipherStateBytes);

      // Clear first flag, which will be set
      // by Initialize() if this is the first transform
      this.ubiParameters.setFirstBlock(false);
      
      // Reset buffer fill count
      this.bytesFilled = 0;
    }
    
    this.inputBuffer[this.bytesFilled++] = src[start++];        
    bytesDone++;
  }
  
  // debug("============================================================ inputBuffer")
  // debug(this.inputBuffer)
  
}

var inputBufferToCipherInput = function(self) {
  for(var i = 0; i < self.cipherStateWords; i++) {
    self.cipherInput[i] = Long.fromBits(util.decodeUInt32R(self.inputBuffer, (i * 8) + 0), util.decodeUInt32R(self.inputBuffer, (i * 8) + 4));
  }  
}

//
// Common to all digests
Skein.prototype.reset = function() {
  initialize_stnd(this);
}

Skein.prototype.processLength = function(bitLength) {
  // this.x[7] = bitLength;
}

// Process (encrypt) one block with Threefish and update internal
// context variables. 
var processBlock = function(self, bytes) {
  // debug("========================================================================= state")
  // debug(self.state)
  // debug("========================================================================= state 0")
  // debug(inspect(self.cipherInput))
  // Set the key to the current state
  self.cipher.setKey(self.state);

  // debug("======================================================================================")
  // debug("  ========================================================================= bytes")
  // debug("  " + bytes)
  // debug("  ========================================================================= tweak")
  // debug("  " + self.ubiParameters.getTweak())
  
  // Update tweak
  self.ubiParameters.addBytesProcessed(bytes);
  
  self.cipher.setTweak(self.ubiParameters.getTweak());
  
  // debug("========================================================================= state 1")
  // debug(inspect(self.cipherInput))


  // debug("  ========================================================================= cipherInput")
  // debug("  " + self.cipherInput)
  // 
  // debug("  ========================================================================= state 0")
  // debug("  " + self.state)
  
  // Encrypt block
  self.state = self.cipher.encryptLong(self.cipherInput, self.state);
  // debug("  ========================================================================= state 1")
  // debug("  " + self.state)
  
  // Feed-forward input with state
  for(var i = 0; i < self.cipherInput.length; i++) {
    self.state[i] = self.state[i].xor(self.cipherInput[i]);
  }

  // debug("========================================================================= state")
  // debug(self.state)
}

var putBytes = function(input, output, index, byteCount) {
  var j = 0;
  var offset = index;
  
  for (var i = 0; i < byteCount; i++) {
    output[offset++] = input[i >> 3].shiftRight(j).and(Long.fromNumber(255)).toNumber()
    j = (j + 8) & 63;
  }  
  return output;
}

//
// Common to all digests
Skein.prototype.digest = function(encoding) {
  // Pad left over space in input buffer with zeros
  // and copy to cipher input buffer
  for(var i = this.bytesFilled; i < this.inputBuffer.length; i++) {
    this.inputBuffer[i] = 0;
  }
  
  // debug("========================================================================= state")
  // debug(this.state)

  inputBufferToCipherInput(this);
  
  // Do final message block
  this.ubiParameters.setFinalBlock(true);
  processBlock(this, this.bytesFilled);
  
  // Clear cipher input
  for(var i = 0; i < this.cipherInput.length; i++) {
    this.cipherInput[i] = Long.ZERO;
  }
  
  // Do output block counter mode output
  var j = 0;
  // debug("============================ outputBytes :: " + this.outputBytes)
  var hash = new Array(this.outputBytes)
  var oldState = new Array(this.cipherStateWords);
  
  // Save old state
  for(var j = 0; j < this.state.length; j++) {
    oldState[j] = this.state[j];
  }
  
  for(var i = 0; i < this.outputBytes; i += this.cipherStateBytes) {
    this.ubiParameters.startNewBlockType(UbiTweak.Out);
    this.ubiParameters.setFinalBlock(true);
    processBlock(this, 8);
    
    var outputSize = this.outputBytes - i;
    if(outputSize > this.cipherStateBytes) {
      outputSize = this.cipherStateBytes;
    }
    
    putBytes(this.state, hash, i, outputSize);  
    
    // Restore old state
    for(var j = 0; j < this.state.length; j++) {
      this.state[j] = oldState[j];
    }
    
    // Increment counter
    this.cipherInput[0] = this.cipherInput[0].add(Long.fromNumber(1));
  }
  
  var output = hash;
  this.reset();  
  // Return based on encoding
  if(encoding == null || encoding === 'binary') {
    return util.arrayToBinaryString(output);
  } else if(encoding === 'hex') {
    return util.toHex(output);
  } else if(encoding === 'array'){
    return output ;    
  }
}
