var debug = require('sys').debug,
  inspect = require('sys').inspect,  
  inherits = require('sys').inherits,  
  util = require('utils'),
  BaseDigest = require('./base').BaseDigest,
  Long = require('long').Long;

const DIGEST_LENGTH = 24;
const BYTE_LENGTH = 64;

var Tiger = exports.Tiger = function() {
  // Tiger variables
  this.buf = [Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, ];
  this.bOff = 0;

  this.x = [Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, Long.ZERO, ];
  this.xOff = 0;
  this.byteCount = Long.ZERO;
  this.a = Long.ZERO;
  this.b = Long.ZERO;
  this.c = Long.ZERO;
  
  // Reset 
  this.reset();
}

Tiger.prototype.getDigestSize = function() {
  return DIGEST_LENGTH;
}

Tiger.prototype.getByteLength = function() {
  return BYTE_LENGTH;
}

Tiger.prototype.getAlgorithmName = function() {
  return "TIGER";
}

Tiger.prototype.processWord = function(src, inOff) {
  this.x[this.xOff++] = Long.fromBits(util.decodeUInt32R(src, inOff + 0), util.decodeUInt32R(src, inOff + 4));
  if (this.xOff == this.x.length) {
    this.processBlock();
  }

  this.bOff = Long.ZERO;
}

const five = Long.fromNumber(5);
const seven = Long.fromNumber(7);
const nine = Long.fromNumber(9);

Tiger.prototype.processBlock = function() {
  var self = this;
  
  //
  // save abc
  //
  var aa = self.a.add(0);
  var bb = self.b.add(0);
  var cc = self.c.add(0);
  
  //
  // rounds and schedule
  //
  roundABC(self, self.x[0], five);
  roundBCA(self, self.x[1], five);
  roundCAB(self, self.x[2], five);
  roundABC(self, self.x[3], five);
  roundBCA(self, self.x[4], five);
  roundCAB(self, self.x[5], five);
  roundABC(self, self.x[6], five);
  roundBCA(self, self.x[7], five);

  keySchedule(self);

  roundCAB(self, self.x[0], seven);
  roundABC(self, self.x[1], seven);
  roundBCA(self, self.x[2], seven);
  roundCAB(self, self.x[3], seven);
  roundABC(self, self.x[4], seven);
  roundBCA(self, self.x[5], seven);
  roundCAB(self, self.x[6], seven);
  roundABC(self, self.x[7], seven);

  keySchedule(self);

  roundBCA(self, self.x[0], nine);
  roundCAB(self, self.x[1], nine);
  roundABC(self, self.x[2], nine);
  roundBCA(self, self.x[3], nine);
  roundCAB(self, self.x[4], nine);
  roundABC(self, self.x[5], nine);
  roundBCA(self, self.x[6], nine);
  roundCAB(self, self.x[7], nine);

  //
  // feed forward
  //
  self.a = self.a.xor(aa);
  self.b = self.b.subtract(bb);
  self.c = self.c.add(cc);

  //
  // clear the x buffer
  //
  self.xOff = 0;
  for(var i = 0; i != self.x.length; i++) {
    self.x[i] = Long.ZERO;
  }  
}

//
// Common to all digests
var update = function(instance, b) {
  instance.buf[instance.bOff++] = b;
  if(instance.bOff == instance.buf.length) {
    instance.processWord(instance.buf, 0)
  }
  
  instance.byteCount = instance.byteCount.add(Long.fromNumber(1));
}

var roundABC = function(self, x, mul) {
   self.c = self.c.xor(x);
   self.a = self.a.subtract(
      t1[self.c.getLowBitsUnsigned() & 0xff]
      .xor(t2[self.c.shiftRight(16).getLowBitsUnsigned() & 0xff])
      .xor(t3[self.c.shiftRight(32).getLowBitsUnsigned() & 0xff])
      .xor(t4[self.c.shiftRight(48).getLowBitsUnsigned() & 0xff])
     );  
   self.b = self.b.add(
      t4[self.c.shiftRight(8).getLowBitsUnsigned() & 0xff]
      .xor(t3[self.c.shiftRight(24).getLowBitsUnsigned() & 0xff])
      .xor(t2[self.c.shiftRight(40).getLowBitsUnsigned() & 0xff])
      .xor(t1[self.c.shiftRight(56).getLowBitsUnsigned() & 0xff])
     );     
   self.b = self.b.multiply(mul);
}

var roundBCA = function(self, x, mul) {
   self.a = self.a.xor(x);
   self.b = self.b.subtract(
      t1[self.a.getLowBitsUnsigned() & 0xff]
      .xor(t2[self.a.shiftRight(16).getLowBitsUnsigned() & 0xff])
      .xor(t3[self.a.shiftRight(32).getLowBitsUnsigned() & 0xff])
      .xor(t4[self.a.shiftRight(48).getLowBitsUnsigned() & 0xff])
     );  
   self.c = self.c.add(
      t4[self.a.shiftRight(8).getLowBitsUnsigned() & 0xff]
      .xor(t3[self.a.shiftRight(24).getLowBitsUnsigned() & 0xff])
      .xor(t2[self.a.shiftRight(40).getLowBitsUnsigned() & 0xff])
      .xor(t1[self.a.shiftRight(56).getLowBitsUnsigned() & 0xff])
     );     
   self.c = self.c.multiply(mul);
}

var roundCAB = function(self, x, mul) {
   self.b = self.b.xor(x);
   self.c = self.c.subtract(
      t1[self.b.getLowBitsUnsigned() & 0xff]
      .xor(t2[self.b.shiftRight(16).getLowBitsUnsigned() & 0xff])
      .xor(t3[self.b.shiftRight(32).getLowBitsUnsigned() & 0xff])
      .xor(t4[self.b.shiftRight(48).getLowBitsUnsigned() & 0xff])
     );  
   self.a = self.a.add(
      t4[self.b.shiftRight(8).getLowBitsUnsigned() & 0xff]
      .xor(t3[self.b.shiftRight(24).getLowBitsUnsigned() & 0xff])
      .xor(t2[self.b.shiftRight(40).getLowBitsUnsigned() & 0xff])
      .xor(t1[self.b.shiftRight(56).getLowBitsUnsigned() & 0xff])
     );     
   self.a = self.a.multiply(mul);
}

const keyconst1 = Long.fromString("A5A5A5A5A5A5A5A5", 16);
const keyconst2 = Long.fromString("0123456789ABCDEF", 16);

var keySchedule = function(self) {
  self.x[0] = self.x[0].subtract(self.x[7].xor(keyconst1))
  self.x[1] = self.x[1].xor(self.x[0]);
  self.x[2] = self.x[2].add(self.x[1]);
  self.x[3] = self.x[3].subtract(self.x[2].xor(self.x[1].not().shiftLeft(19)));
  self.x[4] = self.x[4].xor(self.x[3]);
  self.x[5] = self.x[5].add(self.x[4]);
  self.x[6] = self.x[6].subtract(self.x[5].xor(self.x[4].not().shiftRightUnsigned(23)));
  self.x[7] = self.x[7].xor(self.x[6]);
  self.x[0] = self.x[0].add(self.x[7]);
  self.x[1] = self.x[1].subtract(self.x[0].xor(self.x[7].not().shiftLeft(19)));
  self.x[2] = self.x[2].xor(self.x[1]);
  self.x[3] = self.x[3].add(self.x[2]);
  self.x[4] = self.x[4].subtract(self.x[3].xor(self.x[2].not().shiftRightUnsigned(23)));
  self.x[5] = self.x[5].xor(self.x[4]);
  self.x[6] = self.x[6].add(self.x[5]);
  self.x[7] = self.x[7].subtract(self.x[6].xor(keyconst2))
}


//
// Common to all digests
Tiger.prototype.update = function(src) {
  if(!Array.isArray(src)) src = util.binaryStringToArray(src);
  var inOff = 0;
  var len = src.length;
  
  //
  // fill the current word
  //
  while((this.bOff != 0) && (len > 0)) {
    update(this, src[inOff]);
    inOff++;
    len--;
  }
  
  //
  // process whole words.
  //
  while(len > 8) {
    this.processWord(src, inOff);
    
    inOff += 8;
    len -= 8;
    this.byteCount = this.byteCount.add(Long.fromNumber(8));
  }
  
  //
  // load in the remainder.
  //
  while(len > 0) {
    update(this, src[inOff]);
    inOff++;
    len--;    
  }  
}

Tiger.prototype.finish = function() {
  var bitLength = this.byteCount.shiftLeft(3);
  update(this, 0x01);
  
  while(this.bOff != 0) {
    update(this, 0);
  }
  
  this.processLength(bitLength);
  this.processBlock();
}

//
// Common to all digests
Tiger.prototype.reset = function() {
  this.a = Long.fromString("0123456789ABCDEF", 16);
  this.b = Long.fromString("FEDCBA9876543210", 16);
  this.c = Long.fromString("F096A5B4C3B2E187", 16);
  
  this.xOff = 0;
  for(var i = 0; i != this.x.length; i++) {
    this.x[i] = Long.ZERO;
  }

  this.bOff = 0;
  for(var i = 0; i != this.buf.length; i++) {
      this.buf[i] = Long.ZERO;
  }

  this.byteCount = Long.ZERO;  
}

Tiger.prototype.processLength = function(bitLength) {
  this.x[7] = bitLength;
}

//
// Common to all digests
Tiger.prototype.doFinal = function(output, index) {
  this.finish();
  index = index == null ? 0 : index;
  // Encode in output array
  util.inPlaceEncodeUInt32R(this.a.getLowBits(), output, index + 0);
  util.inPlaceEncodeUInt32R(this.a.getHighBits(), output, index + 4);
  util.inPlaceEncodeUInt32R(this.b.getLowBits(), output, index + 8);
  util.inPlaceEncodeUInt32R(this.b.getHighBits(), output, index + 12);
  util.inPlaceEncodeUInt32R(this.c.getLowBits(), output, index + 16);
  util.inPlaceEncodeUInt32R(this.c.getHighBits(), output, index + 20);  
  this.reset();
  // Return based on encoding
  return DIGEST_LENGTH;
}

/*
 * S-Boxes.
 */
const t1 = [
    Long.fromString("02AAB17CF7E90C5E", 16)   /*    0 */,    Long.fromString("AC424B03E243A8EC", 16)   /*    1 */,
    Long.fromString("72CD5BE30DD5FCD3", 16)   /*    2 */,    Long.fromString("6D019B93F6F97F3A", 16)   /*    3 */,
    Long.fromString("CD9978FFD21F9193", 16)   /*    4 */,    Long.fromString("7573A1C9708029E2", 16)   /*    5 */,
    Long.fromString("B164326B922A83C3", 16)   /*    6 */,    Long.fromString("46883EEE04915870", 16)   /*    7 */,
    Long.fromString("EAACE3057103ECE6", 16)   /*    8 */,    Long.fromString("C54169B808A3535C", 16)   /*    9 */,
    Long.fromString("4CE754918DDEC47C", 16)   /*   10 */,    Long.fromString("0AA2F4DFDC0DF40C", 16)   /*   11 */,
    Long.fromString("10B76F18A74DBEFA", 16)   /*   12 */,    Long.fromString("C6CCB6235AD1AB6A", 16)   /*   13 */,
    Long.fromString("13726121572FE2FF", 16)   /*   14 */,    Long.fromString("1A488C6F199D921E", 16)   /*   15 */,
    Long.fromString("4BC9F9F4DA0007CA", 16)   /*   16 */,    Long.fromString("26F5E6F6E85241C7", 16)   /*   17 */,
    Long.fromString("859079DBEA5947B6", 16)   /*   18 */,    Long.fromString("4F1885C5C99E8C92", 16)   /*   19 */,
    Long.fromString("D78E761EA96F864B", 16)   /*   20 */,    Long.fromString("8E36428C52B5C17D", 16)   /*   21 */,
    Long.fromString("69CF6827373063C1", 16)   /*   22 */,    Long.fromString("B607C93D9BB4C56E", 16)   /*   23 */,
    Long.fromString("7D820E760E76B5EA", 16)   /*   24 */,    Long.fromString("645C9CC6F07FDC42", 16)   /*   25 */,
    Long.fromString("BF38A078243342E0", 16)   /*   26 */,    Long.fromString("5F6B343C9D2E7D04", 16)   /*   27 */,
    Long.fromString("F2C28AEB600B0EC6", 16)   /*   28 */,    Long.fromString("6C0ED85F7254BCAC", 16)   /*   29 */,
    Long.fromString("71592281A4DB4FE5", 16)   /*   30 */,    Long.fromString("1967FA69CE0FED9F", 16)   /*   31 */,
    Long.fromString("FD5293F8B96545DB", 16)   /*   32 */,    Long.fromString("C879E9D7F2A7600B", 16)   /*   33 */,
    Long.fromString("860248920193194E", 16)   /*   34 */,    Long.fromString("A4F9533B2D9CC0B3", 16)   /*   35 */,
    Long.fromString("9053836C15957613", 16)   /*   36 */,    Long.fromString("DB6DCF8AFC357BF1", 16)   /*   37 */,
    Long.fromString("18BEEA7A7A370F57", 16)   /*   38 */,    Long.fromString("037117CA50B99066", 16)   /*   39 */,
    Long.fromString("6AB30A9774424A35", 16)   /*   40 */,    Long.fromString("F4E92F02E325249B", 16)   /*   41 */,
    Long.fromString("7739DB07061CCAE1", 16)   /*   42 */,    Long.fromString("D8F3B49CECA42A05", 16)   /*   43 */,
    Long.fromString("BD56BE3F51382F73", 16)   /*   44 */,    Long.fromString("45FAED5843B0BB28", 16)   /*   45 */,
    Long.fromString("1C813D5C11BF1F83", 16)   /*   46 */,    Long.fromString("8AF0E4B6D75FA169", 16)   /*   47 */,
    Long.fromString("33EE18A487AD9999", 16)   /*   48 */,    Long.fromString("3C26E8EAB1C94410", 16)   /*   49 */,
    Long.fromString("B510102BC0A822F9", 16)   /*   50 */,    Long.fromString("141EEF310CE6123B", 16)   /*   51 */,
    Long.fromString("FC65B90059DDB154", 16)   /*   52 */,    Long.fromString("E0158640C5E0E607", 16)   /*   53 */,
    Long.fromString("884E079826C3A3CF", 16)   /*   54 */,    Long.fromString("930D0D9523C535FD", 16)   /*   55 */,
    Long.fromString("35638D754E9A2B00", 16)   /*   56 */,    Long.fromString("4085FCCF40469DD5", 16)   /*   57 */,
    Long.fromString("C4B17AD28BE23A4C", 16)   /*   58 */,    Long.fromString("CAB2F0FC6A3E6A2E", 16)   /*   59 */,
    Long.fromString("2860971A6B943FCD", 16)   /*   60 */,    Long.fromString("3DDE6EE212E30446", 16)   /*   61 */,
    Long.fromString("6222F32AE01765AE", 16)   /*   62 */,    Long.fromString("5D550BB5478308FE", 16)   /*   63 */,
    Long.fromString("A9EFA98DA0EDA22A", 16)   /*   64 */,    Long.fromString("C351A71686C40DA7", 16)   /*   65 */,
    Long.fromString("1105586D9C867C84", 16)   /*   66 */,    Long.fromString("DCFFEE85FDA22853", 16)   /*   67 */,
    Long.fromString("CCFBD0262C5EEF76", 16)   /*   68 */,    Long.fromString("BAF294CB8990D201", 16)   /*   69 */,
    Long.fromString("E69464F52AFAD975", 16)   /*   70 */,    Long.fromString("94B013AFDF133E14", 16)   /*   71 */,
    Long.fromString("06A7D1A32823C958", 16)   /*   72 */,    Long.fromString("6F95FE5130F61119", 16)   /*   73 */,
    Long.fromString("D92AB34E462C06C0", 16)   /*   74 */,    Long.fromString("ED7BDE33887C71D2", 16)   /*   75 */,
    Long.fromString("79746D6E6518393E", 16)   /*   76 */,    Long.fromString("5BA419385D713329", 16)   /*   77 */,
    Long.fromString("7C1BA6B948A97564", 16)   /*   78 */,    Long.fromString("31987C197BFDAC67", 16)   /*   79 */,
    Long.fromString("DE6C23C44B053D02", 16)   /*   80 */,    Long.fromString("581C49FED002D64D", 16)   /*   81 */,
    Long.fromString("DD474D6338261571", 16)   /*   82 */,    Long.fromString("AA4546C3E473D062", 16)   /*   83 */,
    Long.fromString("928FCE349455F860", 16)   /*   84 */,    Long.fromString("48161BBACAAB94D9", 16)   /*   85 */,
    Long.fromString("63912430770E6F68", 16)   /*   86 */,    Long.fromString("6EC8A5E602C6641C", 16)   /*   87 */,
    Long.fromString("87282515337DDD2B", 16)   /*   88 */,    Long.fromString("2CDA6B42034B701B", 16)   /*   89 */,
    Long.fromString("B03D37C181CB096D", 16)   /*   90 */,    Long.fromString("E108438266C71C6F", 16)   /*   91 */,
    Long.fromString("2B3180C7EB51B255", 16)   /*   92 */,    Long.fromString("DF92B82F96C08BBC", 16)   /*   93 */,
    Long.fromString("5C68C8C0A632F3BA", 16)   /*   94 */,    Long.fromString("5504CC861C3D0556", 16)   /*   95 */,
    Long.fromString("ABBFA4E55FB26B8F", 16)   /*   96 */,    Long.fromString("41848B0AB3BACEB4", 16)   /*   97 */,
    Long.fromString("B334A273AA445D32", 16)   /*   98 */,    Long.fromString("BCA696F0A85AD881", 16)   /*   99 */,
    Long.fromString("24F6EC65B528D56C", 16)   /*  100 */,    Long.fromString("0CE1512E90F4524A", 16)   /*  101 */,
    Long.fromString("4E9DD79D5506D35A", 16)   /*  102 */,    Long.fromString("258905FAC6CE9779", 16)   /*  103 */,
    Long.fromString("2019295B3E109B33", 16)   /*  104 */,    Long.fromString("F8A9478B73A054CC", 16)   /*  105 */,
    Long.fromString("2924F2F934417EB0", 16)   /*  106 */,    Long.fromString("3993357D536D1BC4", 16)   /*  107 */,
    Long.fromString("38A81AC21DB6FF8B", 16)   /*  108 */,    Long.fromString("47C4FBF17D6016BF", 16)   /*  109 */,
    Long.fromString("1E0FAADD7667E3F5", 16)   /*  110 */,    Long.fromString("7ABCFF62938BEB96", 16)   /*  111 */,
    Long.fromString("A78DAD948FC179C9", 16)   /*  112 */,    Long.fromString("8F1F98B72911E50D", 16)   /*  113 */,
    Long.fromString("61E48EAE27121A91", 16)   /*  114 */,    Long.fromString("4D62F7AD31859808", 16)   /*  115 */,
    Long.fromString("ECEBA345EF5CEAEB", 16)   /*  116 */,    Long.fromString("F5CEB25EBC9684CE", 16)   /*  117 */,
    Long.fromString("F633E20CB7F76221", 16)   /*  118 */,    Long.fromString("A32CDF06AB8293E4", 16)   /*  119 */,
    Long.fromString("985A202CA5EE2CA4", 16)   /*  120 */,    Long.fromString("CF0B8447CC8A8FB1", 16)   /*  121 */,
    Long.fromString("9F765244979859A3", 16)   /*  122 */,    Long.fromString("A8D516B1A1240017", 16)   /*  123 */,
    Long.fromString("0BD7BA3EBB5DC726", 16)   /*  124 */,    Long.fromString("E54BCA55B86ADB39", 16)   /*  125 */,
    Long.fromString("1D7A3AFD6C478063", 16)   /*  126 */,    Long.fromString("519EC608E7669EDD", 16)   /*  127 */,
    Long.fromString("0E5715A2D149AA23", 16)   /*  128 */,    Long.fromString("177D4571848FF194", 16)   /*  129 */,
    Long.fromString("EEB55F3241014C22", 16)   /*  130 */,    Long.fromString("0F5E5CA13A6E2EC2", 16)   /*  131 */,
    Long.fromString("8029927B75F5C361", 16)   /*  132 */,    Long.fromString("AD139FABC3D6E436", 16)   /*  133 */,
    Long.fromString("0D5DF1A94CCF402F", 16)   /*  134 */,    Long.fromString("3E8BD948BEA5DFC8", 16)   /*  135 */,
    Long.fromString("A5A0D357BD3FF77E", 16)   /*  136 */,    Long.fromString("A2D12E251F74F645", 16)   /*  137 */,
    Long.fromString("66FD9E525E81A082", 16)   /*  138 */,    Long.fromString("2E0C90CE7F687A49", 16)   /*  139 */,
    Long.fromString("C2E8BCBEBA973BC5", 16)   /*  140 */,    Long.fromString("000001BCE509745F", 16)   /*  141 */,
    Long.fromString("423777BBE6DAB3D6", 16)   /*  142 */,    Long.fromString("D1661C7EAEF06EB5", 16)   /*  143 */,
    Long.fromString("A1781F354DAACFD8", 16)   /*  144 */,    Long.fromString("2D11284A2B16AFFC", 16)   /*  145 */,
    Long.fromString("F1FC4F67FA891D1F", 16)   /*  146 */,    Long.fromString("73ECC25DCB920ADA", 16)   /*  147 */,
    Long.fromString("AE610C22C2A12651", 16)   /*  148 */,    Long.fromString("96E0A810D356B78A", 16)   /*  149 */,
    Long.fromString("5A9A381F2FE7870F", 16)   /*  150 */,    Long.fromString("D5AD62EDE94E5530", 16)   /*  151 */,
    Long.fromString("D225E5E8368D1427", 16)   /*  152 */,    Long.fromString("65977B70C7AF4631", 16)   /*  153 */,
    Long.fromString("99F889B2DE39D74F", 16)   /*  154 */,    Long.fromString("233F30BF54E1D143", 16)   /*  155 */,
    Long.fromString("9A9675D3D9A63C97", 16)   /*  156 */,    Long.fromString("5470554FF334F9A8", 16)   /*  157 */,
    Long.fromString("166ACB744A4F5688", 16)   /*  158 */,    Long.fromString("70C74CAAB2E4AEAD", 16)   /*  159 */,
    Long.fromString("F0D091646F294D12", 16)   /*  160 */,    Long.fromString("57B82A89684031D1", 16)   /*  161 */,
    Long.fromString("EFD95A5A61BE0B6B", 16)   /*  162 */,    Long.fromString("2FBD12E969F2F29A", 16)   /*  163 */,
    Long.fromString("9BD37013FEFF9FE8", 16)   /*  164 */,    Long.fromString("3F9B0404D6085A06", 16)   /*  165 */,
    Long.fromString("4940C1F3166CFE15", 16)   /*  166 */,    Long.fromString("09542C4DCDF3DEFB", 16)   /*  167 */,
    Long.fromString("B4C5218385CD5CE3", 16)   /*  168 */,    Long.fromString("C935B7DC4462A641", 16)   /*  169 */,
    Long.fromString("3417F8A68ED3B63F", 16)   /*  170 */,    Long.fromString("B80959295B215B40", 16)   /*  171 */,
    Long.fromString("F99CDAEF3B8C8572", 16)   /*  172 */,    Long.fromString("018C0614F8FCB95D", 16)   /*  173 */,
    Long.fromString("1B14ACCD1A3ACDF3", 16)   /*  174 */,    Long.fromString("84D471F200BB732D", 16)   /*  175 */,
    Long.fromString("C1A3110E95E8DA16", 16)   /*  176 */,    Long.fromString("430A7220BF1A82B8", 16)   /*  177 */,
    Long.fromString("B77E090D39DF210E", 16)   /*  178 */,    Long.fromString("5EF4BD9F3CD05E9D", 16)   /*  179 */,
    Long.fromString("9D4FF6DA7E57A444", 16)   /*  180 */,    Long.fromString("DA1D60E183D4A5F8", 16)   /*  181 */,
    Long.fromString("B287C38417998E47", 16)   /*  182 */,    Long.fromString("FE3EDC121BB31886", 16)   /*  183 */,
    Long.fromString("C7FE3CCC980CCBEF", 16)   /*  184 */,    Long.fromString("E46FB590189BFD03", 16)   /*  185 */,
    Long.fromString("3732FD469A4C57DC", 16)   /*  186 */,    Long.fromString("7EF700A07CF1AD65", 16)   /*  187 */,
    Long.fromString("59C64468A31D8859", 16)   /*  188 */,    Long.fromString("762FB0B4D45B61F6", 16)   /*  189 */,
    Long.fromString("155BAED099047718", 16)   /*  190 */,    Long.fromString("68755E4C3D50BAA6", 16)   /*  191 */,
    Long.fromString("E9214E7F22D8B4DF", 16)   /*  192 */,    Long.fromString("2ADDBF532EAC95F4", 16)   /*  193 */,
    Long.fromString("32AE3909B4BD0109", 16)   /*  194 */,    Long.fromString("834DF537B08E3450", 16)   /*  195 */,
    Long.fromString("FA209DA84220728D", 16)   /*  196 */,    Long.fromString("9E691D9B9EFE23F7", 16)   /*  197 */,
    Long.fromString("0446D288C4AE8D7F", 16)   /*  198 */,    Long.fromString("7B4CC524E169785B", 16)   /*  199 */,
    Long.fromString("21D87F0135CA1385", 16)   /*  200 */,    Long.fromString("CEBB400F137B8AA5", 16)   /*  201 */,
    Long.fromString("272E2B66580796BE", 16)   /*  202 */,    Long.fromString("3612264125C2B0DE", 16)   /*  203 */,
    Long.fromString("057702BDAD1EFBB2", 16)   /*  204 */,    Long.fromString("D4BABB8EACF84BE9", 16)   /*  205 */,
    Long.fromString("91583139641BC67B", 16)   /*  206 */,    Long.fromString("8BDC2DE08036E024", 16)   /*  207 */,
    Long.fromString("603C8156F49F68ED", 16)   /*  208 */,    Long.fromString("F7D236F7DBEF5111", 16)   /*  209 */,
    Long.fromString("9727C4598AD21E80", 16)   /*  210 */,    Long.fromString("A08A0896670A5FD7", 16)   /*  211 */,
    Long.fromString("CB4A8F4309EBA9CB", 16)   /*  212 */,    Long.fromString("81AF564B0F7036A1", 16)   /*  213 */,
    Long.fromString("C0B99AA778199ABD", 16)   /*  214 */,    Long.fromString("959F1EC83FC8E952", 16)   /*  215 */,
    Long.fromString("8C505077794A81B9", 16)   /*  216 */,    Long.fromString("3ACAAF8F056338F0", 16)   /*  217 */,
    Long.fromString("07B43F50627A6778", 16)   /*  218 */,    Long.fromString("4A44AB49F5ECCC77", 16)   /*  219 */,
    Long.fromString("3BC3D6E4B679EE98", 16)   /*  220 */,    Long.fromString("9CC0D4D1CF14108C", 16)   /*  221 */,
    Long.fromString("4406C00B206BC8A0", 16)   /*  222 */,    Long.fromString("82A18854C8D72D89", 16)   /*  223 */,
    Long.fromString("67E366B35C3C432C", 16)   /*  224 */,    Long.fromString("B923DD61102B37F2", 16)   /*  225 */,
    Long.fromString("56AB2779D884271D", 16)   /*  226 */,    Long.fromString("BE83E1B0FF1525AF", 16)   /*  227 */,
    Long.fromString("FB7C65D4217E49A9", 16)   /*  228 */,    Long.fromString("6BDBE0E76D48E7D4", 16)   /*  229 */,
    Long.fromString("08DF828745D9179E", 16)   /*  230 */,    Long.fromString("22EA6A9ADD53BD34", 16)   /*  231 */,
    Long.fromString("E36E141C5622200A", 16)   /*  232 */,    Long.fromString("7F805D1B8CB750EE", 16)   /*  233 */,
    Long.fromString("AFE5C7A59F58E837", 16)   /*  234 */,    Long.fromString("E27F996A4FB1C23C", 16)   /*  235 */,
    Long.fromString("D3867DFB0775F0D0", 16)   /*  236 */,    Long.fromString("D0E673DE6E88891A", 16)   /*  237 */,
    Long.fromString("123AEB9EAFB86C25", 16)   /*  238 */,    Long.fromString("30F1D5D5C145B895", 16)   /*  239 */,
    Long.fromString("BB434A2DEE7269E7", 16)   /*  240 */,    Long.fromString("78CB67ECF931FA38", 16)   /*  241 */,
    Long.fromString("F33B0372323BBF9C", 16)   /*  242 */,    Long.fromString("52D66336FB279C74", 16)   /*  243 */,
    Long.fromString("505F33AC0AFB4EAA", 16)   /*  244 */,    Long.fromString("E8A5CD99A2CCE187", 16)   /*  245 */,
    Long.fromString("534974801E2D30BB", 16)   /*  246 */,    Long.fromString("8D2D5711D5876D90", 16)   /*  247 */,
    Long.fromString("1F1A412891BC038E", 16)   /*  248 */,    Long.fromString("D6E2E71D82E56648", 16)   /*  249 */,
    Long.fromString("74036C3A497732B7", 16)   /*  250 */,    Long.fromString("89B67ED96361F5AB", 16)   /*  251 */,
    Long.fromString("FFED95D8F1EA02A2", 16)   /*  252 */,    Long.fromString("E72B3BD61464D43D", 16)   /*  253 */,
    Long.fromString("A6300F170BDC4820", 16)   /*  254 */,    Long.fromString("EBC18760ED78A77A", 16)   /*  255 */,
];

const t2 = [
    Long.fromString("E6A6BE5A05A12138", 16)   /*  256 */,    Long.fromString("B5A122A5B4F87C98", 16)   /*  257 */,
    Long.fromString("563C6089140B6990", 16)   /*  258 */,    Long.fromString("4C46CB2E391F5DD5", 16)   /*  259 */,
    Long.fromString("D932ADDBC9B79434", 16)   /*  260 */,    Long.fromString("08EA70E42015AFF5", 16)   /*  261 */,
    Long.fromString("D765A6673E478CF1", 16)   /*  262 */,    Long.fromString("C4FB757EAB278D99", 16)   /*  263 */,
    Long.fromString("DF11C6862D6E0692", 16)   /*  264 */,    Long.fromString("DDEB84F10D7F3B16", 16)   /*  265 */,
    Long.fromString("6F2EF604A665EA04", 16)   /*  266 */,    Long.fromString("4A8E0F0FF0E0DFB3", 16)   /*  267 */,
    Long.fromString("A5EDEEF83DBCBA51", 16)   /*  268 */,    Long.fromString("FC4F0A2A0EA4371E", 16)   /*  269 */,
    Long.fromString("E83E1DA85CB38429", 16)   /*  270 */,    Long.fromString("DC8FF882BA1B1CE2", 16)   /*  271 */,
    Long.fromString("CD45505E8353E80D", 16)   /*  272 */,    Long.fromString("18D19A00D4DB0717", 16)   /*  273 */,
    Long.fromString("34A0CFEDA5F38101", 16)   /*  274 */,    Long.fromString("0BE77E518887CAF2", 16)   /*  275 */,
    Long.fromString("1E341438B3C45136", 16)   /*  276 */,    Long.fromString("E05797F49089CCF9", 16)   /*  277 */,
    Long.fromString("FFD23F9DF2591D14", 16)   /*  278 */,    Long.fromString("543DDA228595C5CD", 16)   /*  279 */,
    Long.fromString("661F81FD99052A33", 16)   /*  280 */,    Long.fromString("8736E641DB0F7B76", 16)   /*  281 */,
    Long.fromString("15227725418E5307", 16)   /*  282 */,    Long.fromString("E25F7F46162EB2FA", 16)   /*  283 */,
    Long.fromString("48A8B2126C13D9FE", 16)   /*  284 */,    Long.fromString("AFDC541792E76EEA", 16)   /*  285 */,
    Long.fromString("03D912BFC6D1898F", 16)   /*  286 */,    Long.fromString("31B1AAFA1B83F51B", 16)   /*  287 */,
    Long.fromString("F1AC2796E42AB7D9", 16)   /*  288 */,    Long.fromString("40A3A7D7FCD2EBAC", 16)   /*  289 */,
    Long.fromString("1056136D0AFBBCC5", 16)   /*  290 */,    Long.fromString("7889E1DD9A6D0C85", 16)   /*  291 */,
    Long.fromString("D33525782A7974AA", 16)   /*  292 */,    Long.fromString("A7E25D09078AC09B", 16)   /*  293 */,
    Long.fromString("BD4138B3EAC6EDD0", 16)   /*  294 */,    Long.fromString("920ABFBE71EB9E70", 16)   /*  295 */,
    Long.fromString("A2A5D0F54FC2625C", 16)   /*  296 */,    Long.fromString("C054E36B0B1290A3", 16)   /*  297 */,
    Long.fromString("F6DD59FF62FE932B", 16)   /*  298 */,    Long.fromString("3537354511A8AC7D", 16)   /*  299 */,
    Long.fromString("CA845E9172FADCD4", 16)   /*  300 */,    Long.fromString("84F82B60329D20DC", 16)   /*  301 */,
    Long.fromString("79C62CE1CD672F18", 16)   /*  302 */,    Long.fromString("8B09A2ADD124642C", 16)   /*  303 */,
    Long.fromString("D0C1E96A19D9E726", 16)   /*  304 */,    Long.fromString("5A786A9B4BA9500C", 16)   /*  305 */,
    Long.fromString("0E020336634C43F3", 16)   /*  306 */,    Long.fromString("C17B474AEB66D822", 16)   /*  307 */,
    Long.fromString("6A731AE3EC9BAAC2", 16)   /*  308 */,    Long.fromString("8226667AE0840258", 16)   /*  309 */,
    Long.fromString("67D4567691CAECA5", 16)   /*  310 */,    Long.fromString("1D94155C4875ADB5", 16)   /*  311 */,
    Long.fromString("6D00FD985B813FDF", 16)   /*  312 */,    Long.fromString("51286EFCB774CD06", 16)   /*  313 */,
    Long.fromString("5E8834471FA744AF", 16)   /*  314 */,    Long.fromString("F72CA0AEE761AE2E", 16)   /*  315 */,
    Long.fromString("BE40E4CDAEE8E09A", 16)   /*  316 */,    Long.fromString("E9970BBB5118F665", 16)   /*  317 */,
    Long.fromString("726E4BEB33DF1964", 16)   /*  318 */,    Long.fromString("703B000729199762", 16)   /*  319 */,
    Long.fromString("4631D816F5EF30A7", 16)   /*  320 */,    Long.fromString("B880B5B51504A6BE", 16)   /*  321 */,
    Long.fromString("641793C37ED84B6C", 16)   /*  322 */,    Long.fromString("7B21ED77F6E97D96", 16)   /*  323 */,
    Long.fromString("776306312EF96B73", 16)   /*  324 */,    Long.fromString("AE528948E86FF3F4", 16)   /*  325 */,
    Long.fromString("53DBD7F286A3F8F8", 16)   /*  326 */,    Long.fromString("16CADCE74CFC1063", 16)   /*  327 */,
    Long.fromString("005C19BDFA52C6DD", 16)   /*  328 */,    Long.fromString("68868F5D64D46AD3", 16)   /*  329 */,
    Long.fromString("3A9D512CCF1E186A", 16)   /*  330 */,    Long.fromString("367E62C2385660AE", 16)   /*  331 */,
    Long.fromString("E359E7EA77DCB1D7", 16)   /*  332 */,    Long.fromString("526C0773749ABE6E", 16)   /*  333 */,
    Long.fromString("735AE5F9D09F734B", 16)   /*  334 */,    Long.fromString("493FC7CC8A558BA8", 16)   /*  335 */,
    Long.fromString("B0B9C1533041AB45", 16)   /*  336 */,    Long.fromString("321958BA470A59BD", 16)   /*  337 */,
    Long.fromString("852DB00B5F46C393", 16)   /*  338 */,    Long.fromString("91209B2BD336B0E5", 16)   /*  339 */,
    Long.fromString("6E604F7D659EF19F", 16)   /*  340 */,    Long.fromString("B99A8AE2782CCB24", 16)   /*  341 */,
    Long.fromString("CCF52AB6C814C4C7", 16)   /*  342 */,    Long.fromString("4727D9AFBE11727B", 16)   /*  343 */,
    Long.fromString("7E950D0C0121B34D", 16)   /*  344 */,    Long.fromString("756F435670AD471F", 16)   /*  345 */,
    Long.fromString("F5ADD442615A6849", 16)   /*  346 */,    Long.fromString("4E87E09980B9957A", 16)   /*  347 */,
    Long.fromString("2ACFA1DF50AEE355", 16)   /*  348 */,    Long.fromString("D898263AFD2FD556", 16)   /*  349 */,
    Long.fromString("C8F4924DD80C8FD6", 16)   /*  350 */,    Long.fromString("CF99CA3D754A173A", 16)   /*  351 */,
    Long.fromString("FE477BACAF91BF3C", 16)   /*  352 */,    Long.fromString("ED5371F6D690C12D", 16)   /*  353 */,
    Long.fromString("831A5C285E687094", 16)   /*  354 */,    Long.fromString("C5D3C90A3708A0A4", 16)   /*  355 */,
    Long.fromString("0F7F903717D06580", 16)   /*  356 */,    Long.fromString("19F9BB13B8FDF27F", 16)   /*  357 */,
    Long.fromString("B1BD6F1B4D502843", 16)   /*  358 */,    Long.fromString("1C761BA38FFF4012", 16)   /*  359 */,
    Long.fromString("0D1530C4E2E21F3B", 16)   /*  360 */,    Long.fromString("8943CE69A7372C8A", 16)   /*  361 */,
    Long.fromString("E5184E11FEB5CE66", 16)   /*  362 */,    Long.fromString("618BDB80BD736621", 16)   /*  363 */,
    Long.fromString("7D29BAD68B574D0B", 16)   /*  364 */,    Long.fromString("81BB613E25E6FE5B", 16)   /*  365 */,
    Long.fromString("071C9C10BC07913F", 16)   /*  366 */,    Long.fromString("C7BEEB7909AC2D97", 16)   /*  367 */,
    Long.fromString("C3E58D353BC5D757", 16)   /*  368 */,    Long.fromString("EB017892F38F61E8", 16)   /*  369 */,
    Long.fromString("D4EFFB9C9B1CC21A", 16)   /*  370 */,    Long.fromString("99727D26F494F7AB", 16)   /*  371 */,
    Long.fromString("A3E063A2956B3E03", 16)   /*  372 */,    Long.fromString("9D4A8B9A4AA09C30", 16)   /*  373 */,
    Long.fromString("3F6AB7D500090FB4", 16)   /*  374 */,    Long.fromString("9CC0F2A057268AC0", 16)   /*  375 */,
    Long.fromString("3DEE9D2DEDBF42D1", 16)   /*  376 */,    Long.fromString("330F49C87960A972", 16)   /*  377 */,
    Long.fromString("C6B2720287421B41", 16)   /*  378 */,    Long.fromString("0AC59EC07C00369C", 16)   /*  379 */,
    Long.fromString("EF4EAC49CB353425", 16)   /*  380 */,    Long.fromString("F450244EEF0129D8", 16)   /*  381 */,
    Long.fromString("8ACC46E5CAF4DEB6", 16)   /*  382 */,    Long.fromString("2FFEAB63989263F7", 16)   /*  383 */,
    Long.fromString("8F7CB9FE5D7A4578", 16)   /*  384 */,    Long.fromString("5BD8F7644E634635", 16)   /*  385 */,
    Long.fromString("427A7315BF2DC900", 16)   /*  386 */,    Long.fromString("17D0C4AA2125261C", 16)   /*  387 */,
    Long.fromString("3992486C93518E50", 16)   /*  388 */,    Long.fromString("B4CBFEE0A2D7D4C3", 16)   /*  389 */,
    Long.fromString("7C75D6202C5DDD8D", 16)   /*  390 */,    Long.fromString("DBC295D8E35B6C61", 16)   /*  391 */,
    Long.fromString("60B369D302032B19", 16)   /*  392 */,    Long.fromString("CE42685FDCE44132", 16)   /*  393 */,
    Long.fromString("06F3DDB9DDF65610", 16)   /*  394 */,    Long.fromString("8EA4D21DB5E148F0", 16)   /*  395 */,
    Long.fromString("20B0FCE62FCD496F", 16)   /*  396 */,    Long.fromString("2C1B912358B0EE31", 16)   /*  397 */,
    Long.fromString("B28317B818F5A308", 16)   /*  398 */,    Long.fromString("A89C1E189CA6D2CF", 16)   /*  399 */,
    Long.fromString("0C6B18576AAADBC8", 16)   /*  400 */,    Long.fromString("B65DEAA91299FAE3", 16)   /*  401 */,
    Long.fromString("FB2B794B7F1027E7", 16)   /*  402 */,    Long.fromString("04E4317F443B5BEB", 16)   /*  403 */,
    Long.fromString("4B852D325939D0A6", 16)   /*  404 */,    Long.fromString("D5AE6BEEFB207FFC", 16)   /*  405 */,
    Long.fromString("309682B281C7D374", 16)   /*  406 */,    Long.fromString("BAE309A194C3B475", 16)   /*  407 */,
    Long.fromString("8CC3F97B13B49F05", 16)   /*  408 */,    Long.fromString("98A9422FF8293967", 16)   /*  409 */,
    Long.fromString("244B16B01076FF7C", 16)   /*  410 */,    Long.fromString("F8BF571C663D67EE", 16)   /*  411 */,
    Long.fromString("1F0D6758EEE30DA1", 16)   /*  412 */,    Long.fromString("C9B611D97ADEB9B7", 16)   /*  413 */,
    Long.fromString("B7AFD5887B6C57A2", 16)   /*  414 */,    Long.fromString("6290AE846B984FE1", 16)   /*  415 */,
    Long.fromString("94DF4CDEACC1A5FD", 16)   /*  416 */,    Long.fromString("058A5BD1C5483AFF", 16)   /*  417 */,
    Long.fromString("63166CC142BA3C37", 16)   /*  418 */,    Long.fromString("8DB8526EB2F76F40", 16)   /*  419 */,
    Long.fromString("E10880036F0D6D4E", 16)   /*  420 */,    Long.fromString("9E0523C9971D311D", 16)   /*  421 */,
    Long.fromString("45EC2824CC7CD691", 16)   /*  422 */,    Long.fromString("575B8359E62382C9", 16)   /*  423 */,
    Long.fromString("FA9E400DC4889995", 16)   /*  424 */,    Long.fromString("D1823ECB45721568", 16)   /*  425 */,
    Long.fromString("DAFD983B8206082F", 16)   /*  426 */,    Long.fromString("AA7D29082386A8CB", 16)   /*  427 */,
    Long.fromString("269FCD4403B87588", 16)   /*  428 */,    Long.fromString("1B91F5F728BDD1E0", 16)   /*  429 */,
    Long.fromString("E4669F39040201F6", 16)   /*  430 */,    Long.fromString("7A1D7C218CF04ADE", 16)   /*  431 */,
    Long.fromString("65623C29D79CE5CE", 16)   /*  432 */,    Long.fromString("2368449096C00BB1", 16)   /*  433 */,
    Long.fromString("AB9BF1879DA503BA", 16)   /*  434 */,    Long.fromString("BC23ECB1A458058E", 16)   /*  435 */,
    Long.fromString("9A58DF01BB401ECC", 16)   /*  436 */,    Long.fromString("A070E868A85F143D", 16)   /*  437 */,
    Long.fromString("4FF188307DF2239E", 16)   /*  438 */,    Long.fromString("14D565B41A641183", 16)   /*  439 */,
    Long.fromString("EE13337452701602", 16)   /*  440 */,    Long.fromString("950E3DCF3F285E09", 16)   /*  441 */,
    Long.fromString("59930254B9C80953", 16)   /*  442 */,    Long.fromString("3BF299408930DA6D", 16)   /*  443 */,
    Long.fromString("A955943F53691387", 16)   /*  444 */,    Long.fromString("A15EDECAA9CB8784", 16)   /*  445 */,
    Long.fromString("29142127352BE9A0", 16)   /*  446 */,    Long.fromString("76F0371FFF4E7AFB", 16)   /*  447 */,
    Long.fromString("0239F450274F2228", 16)   /*  448 */,    Long.fromString("BB073AF01D5E868B", 16)   /*  449 */,
    Long.fromString("BFC80571C10E96C1", 16)   /*  450 */,    Long.fromString("D267088568222E23", 16)   /*  451 */,
    Long.fromString("9671A3D48E80B5B0", 16)   /*  452 */,    Long.fromString("55B5D38AE193BB81", 16)   /*  453 */,
    Long.fromString("693AE2D0A18B04B8", 16)   /*  454 */,    Long.fromString("5C48B4ECADD5335F", 16)   /*  455 */,
    Long.fromString("FD743B194916A1CA", 16)   /*  456 */,    Long.fromString("2577018134BE98C4", 16)   /*  457 */,
    Long.fromString("E77987E83C54A4AD", 16)   /*  458 */,    Long.fromString("28E11014DA33E1B9", 16)   /*  459 */,
    Long.fromString("270CC59E226AA213", 16)   /*  460 */,    Long.fromString("71495F756D1A5F60", 16)   /*  461 */,
    Long.fromString("9BE853FB60AFEF77", 16)   /*  462 */,    Long.fromString("ADC786A7F7443DBF", 16)   /*  463 */,
    Long.fromString("0904456173B29A82", 16)   /*  464 */,    Long.fromString("58BC7A66C232BD5E", 16)   /*  465 */,
    Long.fromString("F306558C673AC8B2", 16)   /*  466 */,    Long.fromString("41F639C6B6C9772A", 16)   /*  467 */,
    Long.fromString("216DEFE99FDA35DA", 16)   /*  468 */,    Long.fromString("11640CC71C7BE615", 16)   /*  469 */,
    Long.fromString("93C43694565C5527", 16)   /*  470 */,    Long.fromString("EA038E6246777839", 16)   /*  471 */,
    Long.fromString("F9ABF3CE5A3E2469", 16)   /*  472 */,    Long.fromString("741E768D0FD312D2", 16)   /*  473 */,
    Long.fromString("0144B883CED652C6", 16)   /*  474 */,    Long.fromString("C20B5A5BA33F8552", 16)   /*  475 */,
    Long.fromString("1AE69633C3435A9D", 16)   /*  476 */,    Long.fromString("97A28CA4088CFDEC", 16)   /*  477 */,
    Long.fromString("8824A43C1E96F420", 16)   /*  478 */,    Long.fromString("37612FA66EEEA746", 16)   /*  479 */,
    Long.fromString("6B4CB165F9CF0E5A", 16)   /*  480 */,    Long.fromString("43AA1C06A0ABFB4A", 16)   /*  481 */,
    Long.fromString("7F4DC26FF162796B", 16)   /*  482 */,    Long.fromString("6CBACC8E54ED9B0F", 16)   /*  483 */,
    Long.fromString("A6B7FFEFD2BB253E", 16)   /*  484 */,    Long.fromString("2E25BC95B0A29D4F", 16)   /*  485 */,
    Long.fromString("86D6A58BDEF1388C", 16)   /*  486 */,    Long.fromString("DED74AC576B6F054", 16)   /*  487 */,
    Long.fromString("8030BDBC2B45805D", 16)   /*  488 */,    Long.fromString("3C81AF70E94D9289", 16)   /*  489 */,
    Long.fromString("3EFF6DDA9E3100DB", 16)   /*  490 */,    Long.fromString("B38DC39FDFCC8847", 16)   /*  491 */,
    Long.fromString("123885528D17B87E", 16)   /*  492 */,    Long.fromString("F2DA0ED240B1B642", 16)   /*  493 */,
    Long.fromString("44CEFADCD54BF9A9", 16)   /*  494 */,    Long.fromString("1312200E433C7EE6", 16)   /*  495 */,
    Long.fromString("9FFCC84F3A78C748", 16)   /*  496 */,    Long.fromString("F0CD1F72248576BB", 16)   /*  497 */,
    Long.fromString("EC6974053638CFE4", 16)   /*  498 */,    Long.fromString("2BA7B67C0CEC4E4C", 16)   /*  499 */,
    Long.fromString("AC2F4DF3E5CE32ED", 16)   /*  500 */,    Long.fromString("CB33D14326EA4C11", 16)   /*  501 */,
    Long.fromString("A4E9044CC77E58BC", 16)   /*  502 */,    Long.fromString("5F513293D934FCEF", 16)   /*  503 */,
    Long.fromString("5DC9645506E55444", 16)   /*  504 */,    Long.fromString("50DE418F317DE40A", 16)   /*  505 */,
    Long.fromString("388CB31A69DDE259", 16)   /*  506 */,    Long.fromString("2DB4A83455820A86", 16)   /*  507 */,
    Long.fromString("9010A91E84711AE9", 16)   /*  508 */,    Long.fromString("4DF7F0B7B1498371", 16)   /*  509 */,
    Long.fromString("D62A2EABC0977179", 16)   /*  510 */,    Long.fromString("22FAC097AA8D5C0E", 16)   /*  511 */,
];

const t3 = [
    Long.fromString("F49FCC2FF1DAF39B", 16)   /*  512 */,    Long.fromString("487FD5C66FF29281", 16)   /*  513 */,
    Long.fromString("E8A30667FCDCA83F", 16)   /*  514 */,    Long.fromString("2C9B4BE3D2FCCE63", 16)   /*  515 */,
    Long.fromString("DA3FF74B93FBBBC2", 16)   /*  516 */,    Long.fromString("2FA165D2FE70BA66", 16)   /*  517 */,
    Long.fromString("A103E279970E93D4", 16)   /*  518 */,    Long.fromString("BECDEC77B0E45E71", 16)   /*  519 */,
    Long.fromString("CFB41E723985E497", 16)   /*  520 */,    Long.fromString("B70AAA025EF75017", 16)   /*  521 */,
    Long.fromString("D42309F03840B8E0", 16)   /*  522 */,    Long.fromString("8EFC1AD035898579", 16)   /*  523 */,
    Long.fromString("96C6920BE2B2ABC5", 16)   /*  524 */,    Long.fromString("66AF4163375A9172", 16)   /*  525 */,
    Long.fromString("2174ABDCCA7127FB", 16)   /*  526 */,    Long.fromString("B33CCEA64A72FF41", 16)   /*  527 */,
    Long.fromString("F04A4933083066A5", 16)   /*  528 */,    Long.fromString("8D970ACDD7289AF5", 16)   /*  529 */,
    Long.fromString("8F96E8E031C8C25E", 16)   /*  530 */,    Long.fromString("F3FEC02276875D47", 16)   /*  531 */,
    Long.fromString("EC7BF310056190DD", 16)   /*  532 */,    Long.fromString("F5ADB0AEBB0F1491", 16)   /*  533 */,
    Long.fromString("9B50F8850FD58892", 16)   /*  534 */,    Long.fromString("4975488358B74DE8", 16)   /*  535 */,
    Long.fromString("A3354FF691531C61", 16)   /*  536 */,    Long.fromString("0702BBE481D2C6EE", 16)   /*  537 */,
    Long.fromString("89FB24057DEDED98", 16)   /*  538 */,    Long.fromString("AC3075138596E902", 16)   /*  539 */,
    Long.fromString("1D2D3580172772ED", 16)   /*  540 */,    Long.fromString("EB738FC28E6BC30D", 16)   /*  541 */,
    Long.fromString("5854EF8F63044326", 16)   /*  542 */,    Long.fromString("9E5C52325ADD3BBE", 16)   /*  543 */,
    Long.fromString("90AA53CF325C4623", 16)   /*  544 */,    Long.fromString("C1D24D51349DD067", 16)   /*  545 */,
    Long.fromString("2051CFEEA69EA624", 16)   /*  546 */,    Long.fromString("13220F0A862E7E4F", 16)   /*  547 */,
    Long.fromString("CE39399404E04864", 16)   /*  548 */,    Long.fromString("D9C42CA47086FCB7", 16)   /*  549 */,
    Long.fromString("685AD2238A03E7CC", 16)   /*  550 */,    Long.fromString("066484B2AB2FF1DB", 16)   /*  551 */,
    Long.fromString("FE9D5D70EFBF79EC", 16)   /*  552 */,    Long.fromString("5B13B9DD9C481854", 16)   /*  553 */,
    Long.fromString("15F0D475ED1509AD", 16)   /*  554 */,    Long.fromString("0BEBCD060EC79851", 16)   /*  555 */,
    Long.fromString("D58C6791183AB7F8", 16)   /*  556 */,    Long.fromString("D1187C5052F3EEE4", 16)   /*  557 */,
    Long.fromString("C95D1192E54E82FF", 16)   /*  558 */,    Long.fromString("86EEA14CB9AC6CA2", 16)   /*  559 */,
    Long.fromString("3485BEB153677D5D", 16)   /*  560 */,    Long.fromString("DD191D781F8C492A", 16)   /*  561 */,
    Long.fromString("F60866BAA784EBF9", 16)   /*  562 */,    Long.fromString("518F643BA2D08C74", 16)   /*  563 */,
    Long.fromString("8852E956E1087C22", 16)   /*  564 */,    Long.fromString("A768CB8DC410AE8D", 16)   /*  565 */,
    Long.fromString("38047726BFEC8E1A", 16)   /*  566 */,    Long.fromString("A67738B4CD3B45AA", 16)   /*  567 */,
    Long.fromString("AD16691CEC0DDE19", 16)   /*  568 */,    Long.fromString("C6D4319380462E07", 16)   /*  569 */,
    Long.fromString("C5A5876D0BA61938", 16)   /*  570 */,    Long.fromString("16B9FA1FA58FD840", 16)   /*  571 */,
    Long.fromString("188AB1173CA74F18", 16)   /*  572 */,    Long.fromString("ABDA2F98C99C021F", 16)   /*  573 */,
    Long.fromString("3E0580AB134AE816", 16)   /*  574 */,    Long.fromString("5F3B05B773645ABB", 16)   /*  575 */,
    Long.fromString("2501A2BE5575F2F6", 16)   /*  576 */,    Long.fromString("1B2F74004E7E8BA9", 16)   /*  577 */,
    Long.fromString("1CD7580371E8D953", 16)   /*  578 */,    Long.fromString("7F6ED89562764E30", 16)   /*  579 */,
    Long.fromString("B15926FF596F003D", 16)   /*  580 */,    Long.fromString("9F65293DA8C5D6B9", 16)   /*  581 */,
    Long.fromString("6ECEF04DD690F84C", 16)   /*  582 */,    Long.fromString("4782275FFF33AF88", 16)   /*  583 */,
    Long.fromString("E41433083F820801", 16)   /*  584 */,    Long.fromString("FD0DFE409A1AF9B5", 16)   /*  585 */,
    Long.fromString("4325A3342CDB396B", 16)   /*  586 */,    Long.fromString("8AE77E62B301B252", 16)   /*  587 */,
    Long.fromString("C36F9E9F6655615A", 16)   /*  588 */,    Long.fromString("85455A2D92D32C09", 16)   /*  589 */,
    Long.fromString("F2C7DEA949477485", 16)   /*  590 */,    Long.fromString("63CFB4C133A39EBA", 16)   /*  591 */,
    Long.fromString("83B040CC6EBC5462", 16)   /*  592 */,    Long.fromString("3B9454C8FDB326B0", 16)   /*  593 */,
    Long.fromString("56F56A9E87FFD78C", 16)   /*  594 */,    Long.fromString("2DC2940D99F42BC6", 16)   /*  595 */,
    Long.fromString("98F7DF096B096E2D", 16)   /*  596 */,    Long.fromString("19A6E01E3AD852BF", 16)   /*  597 */,
    Long.fromString("42A99CCBDBD4B40B", 16)   /*  598 */,    Long.fromString("A59998AF45E9C559", 16)   /*  599 */,
    Long.fromString("366295E807D93186", 16)   /*  600 */,    Long.fromString("6B48181BFAA1F773", 16)   /*  601 */,
    Long.fromString("1FEC57E2157A0A1D", 16)   /*  602 */,    Long.fromString("4667446AF6201AD5", 16)   /*  603 */,
    Long.fromString("E615EBCACFB0F075", 16)   /*  604 */,    Long.fromString("B8F31F4F68290778", 16)   /*  605 */,
    Long.fromString("22713ED6CE22D11E", 16)   /*  606 */,    Long.fromString("3057C1A72EC3C93B", 16)   /*  607 */,
    Long.fromString("CB46ACC37C3F1F2F", 16)   /*  608 */,    Long.fromString("DBB893FD02AAF50E", 16)   /*  609 */,
    Long.fromString("331FD92E600B9FCF", 16)   /*  610 */,    Long.fromString("A498F96148EA3AD6", 16)   /*  611 */,
    Long.fromString("A8D8426E8B6A83EA", 16)   /*  612 */,    Long.fromString("A089B274B7735CDC", 16)   /*  613 */,
    Long.fromString("87F6B3731E524A11", 16)   /*  614 */,    Long.fromString("118808E5CBC96749", 16)   /*  615 */,
    Long.fromString("9906E4C7B19BD394", 16)   /*  616 */,    Long.fromString("AFED7F7E9B24A20C", 16)   /*  617 */,
    Long.fromString("6509EADEEB3644A7", 16)   /*  618 */,    Long.fromString("6C1EF1D3E8EF0EDE", 16)   /*  619 */,
    Long.fromString("B9C97D43E9798FB4", 16)   /*  620 */,    Long.fromString("A2F2D784740C28A3", 16)   /*  621 */,
    Long.fromString("7B8496476197566F", 16)   /*  622 */,    Long.fromString("7A5BE3E6B65F069D", 16)   /*  623 */,
    Long.fromString("F96330ED78BE6F10", 16)   /*  624 */,    Long.fromString("EEE60DE77A076A15", 16)   /*  625 */,
    Long.fromString("2B4BEE4AA08B9BD0", 16)   /*  626 */,    Long.fromString("6A56A63EC7B8894E", 16)   /*  627 */,
    Long.fromString("02121359BA34FEF4", 16)   /*  628 */,    Long.fromString("4CBF99F8283703FC", 16)   /*  629 */,
    Long.fromString("398071350CAF30C8", 16)   /*  630 */,    Long.fromString("D0A77A89F017687A", 16)   /*  631 */,
    Long.fromString("F1C1A9EB9E423569", 16)   /*  632 */,    Long.fromString("8C7976282DEE8199", 16)   /*  633 */,
    Long.fromString("5D1737A5DD1F7ABD", 16)   /*  634 */,    Long.fromString("4F53433C09A9FA80", 16)   /*  635 */,
    Long.fromString("FA8B0C53DF7CA1D9", 16)   /*  636 */,    Long.fromString("3FD9DCBC886CCB77", 16)   /*  637 */,
    Long.fromString("C040917CA91B4720", 16)   /*  638 */,    Long.fromString("7DD00142F9D1DCDF", 16)   /*  639 */,
    Long.fromString("8476FC1D4F387B58", 16)   /*  640 */,    Long.fromString("23F8E7C5F3316503", 16)   /*  641 */,
    Long.fromString("032A2244E7E37339", 16)   /*  642 */,    Long.fromString("5C87A5D750F5A74B", 16)   /*  643 */,
    Long.fromString("082B4CC43698992E", 16)   /*  644 */,    Long.fromString("DF917BECB858F63C", 16)   /*  645 */,
    Long.fromString("3270B8FC5BF86DDA", 16)   /*  646 */,    Long.fromString("10AE72BB29B5DD76", 16)   /*  647 */,
    Long.fromString("576AC94E7700362B", 16)   /*  648 */,    Long.fromString("1AD112DAC61EFB8F", 16)   /*  649 */,
    Long.fromString("691BC30EC5FAA427", 16)   /*  650 */,    Long.fromString("FF246311CC327143", 16)   /*  651 */,
    Long.fromString("3142368E30E53206", 16)   /*  652 */,    Long.fromString("71380E31E02CA396", 16)   /*  653 */,
    Long.fromString("958D5C960AAD76F1", 16)   /*  654 */,    Long.fromString("F8D6F430C16DA536", 16)   /*  655 */,
    Long.fromString("C8FFD13F1BE7E1D2", 16)   /*  656 */,    Long.fromString("7578AE66004DDBE1", 16)   /*  657 */,
    Long.fromString("05833F01067BE646", 16)   /*  658 */,    Long.fromString("BB34B5AD3BFE586D", 16)   /*  659 */,
    Long.fromString("095F34C9A12B97F0", 16)   /*  660 */,    Long.fromString("247AB64525D60CA8", 16)   /*  661 */,
    Long.fromString("DCDBC6F3017477D1", 16)   /*  662 */,    Long.fromString("4A2E14D4DECAD24D", 16)   /*  663 */,
    Long.fromString("BDB5E6D9BE0A1EEB", 16)   /*  664 */,    Long.fromString("2A7E70F7794301AB", 16)   /*  665 */,
    Long.fromString("DEF42D8A270540FD", 16)   /*  666 */,    Long.fromString("01078EC0A34C22C1", 16)   /*  667 */,
    Long.fromString("E5DE511AF4C16387", 16)   /*  668 */,    Long.fromString("7EBB3A52BD9A330A", 16)   /*  669 */,
    Long.fromString("77697857AA7D6435", 16)   /*  670 */,    Long.fromString("004E831603AE4C32", 16)   /*  671 */,
    Long.fromString("E7A21020AD78E312", 16)   /*  672 */,    Long.fromString("9D41A70C6AB420F2", 16)   /*  673 */,
    Long.fromString("28E06C18EA1141E6", 16)   /*  674 */,    Long.fromString("D2B28CBD984F6B28", 16)   /*  675 */,
    Long.fromString("26B75F6C446E9D83", 16)   /*  676 */,    Long.fromString("BA47568C4D418D7F", 16)   /*  677 */,
    Long.fromString("D80BADBFE6183D8E", 16)   /*  678 */,    Long.fromString("0E206D7F5F166044", 16)   /*  679 */,
    Long.fromString("E258A43911CBCA3E", 16)   /*  680 */,    Long.fromString("723A1746B21DC0BC", 16)   /*  681 */,
    Long.fromString("C7CAA854F5D7CDD3", 16)   /*  682 */,    Long.fromString("7CAC32883D261D9C", 16)   /*  683 */,
    Long.fromString("7690C26423BA942C", 16)   /*  684 */,    Long.fromString("17E55524478042B8", 16)   /*  685 */,
    Long.fromString("E0BE477656A2389F", 16)   /*  686 */,    Long.fromString("4D289B5E67AB2DA0", 16)   /*  687 */,
    Long.fromString("44862B9C8FBBFD31", 16)   /*  688 */,    Long.fromString("B47CC8049D141365", 16)   /*  689 */,
    Long.fromString("822C1B362B91C793", 16)   /*  690 */,    Long.fromString("4EB14655FB13DFD8", 16)   /*  691 */,
    Long.fromString("1ECBBA0714E2A97B", 16)   /*  692 */,    Long.fromString("6143459D5CDE5F14", 16)   /*  693 */,
    Long.fromString("53A8FBF1D5F0AC89", 16)   /*  694 */,    Long.fromString("97EA04D81C5E5B00", 16)   /*  695 */,
    Long.fromString("622181A8D4FDB3F3", 16)   /*  696 */,    Long.fromString("E9BCD341572A1208", 16)   /*  697 */,
    Long.fromString("1411258643CCE58A", 16)   /*  698 */,    Long.fromString("9144C5FEA4C6E0A4", 16)   /*  699 */,
    Long.fromString("0D33D06565CF620F", 16)   /*  700 */,    Long.fromString("54A48D489F219CA1", 16)   /*  701 */,
    Long.fromString("C43E5EAC6D63C821", 16)   /*  702 */,    Long.fromString("A9728B3A72770DAF", 16)   /*  703 */,
    Long.fromString("D7934E7B20DF87EF", 16)   /*  704 */,    Long.fromString("E35503B61A3E86E5", 16)   /*  705 */,
    Long.fromString("CAE321FBC819D504", 16)   /*  706 */,    Long.fromString("129A50B3AC60BFA6", 16)   /*  707 */,
    Long.fromString("CD5E68EA7E9FB6C3", 16)   /*  708 */,    Long.fromString("B01C90199483B1C7", 16)   /*  709 */,
    Long.fromString("3DE93CD5C295376C", 16)   /*  710 */,    Long.fromString("AED52EDF2AB9AD13", 16)   /*  711 */,
    Long.fromString("2E60F512C0A07884", 16)   /*  712 */,    Long.fromString("BC3D86A3E36210C9", 16)   /*  713 */,
    Long.fromString("35269D9B163951CE", 16)   /*  714 */,    Long.fromString("0C7D6E2AD0CDB5FA", 16)   /*  715 */,
    Long.fromString("59E86297D87F5733", 16)   /*  716 */,    Long.fromString("298EF221898DB0E7", 16)   /*  717 */,
    Long.fromString("55000029D1A5AA7E", 16)   /*  718 */,    Long.fromString("8BC08AE1B5061B45", 16)   /*  719 */,
    Long.fromString("C2C31C2B6C92703A", 16)   /*  720 */,    Long.fromString("94CC596BAF25EF42", 16)   /*  721 */,
    Long.fromString("0A1D73DB22540456", 16)   /*  722 */,    Long.fromString("04B6A0F9D9C4179A", 16)   /*  723 */,
    Long.fromString("EFFDAFA2AE3D3C60", 16)   /*  724 */,    Long.fromString("F7C8075BB49496C4", 16)   /*  725 */,
    Long.fromString("9CC5C7141D1CD4E3", 16)   /*  726 */,    Long.fromString("78BD1638218E5534", 16)   /*  727 */,
    Long.fromString("B2F11568F850246A", 16)   /*  728 */,    Long.fromString("EDFABCFA9502BC29", 16)   /*  729 */,
    Long.fromString("796CE5F2DA23051B", 16)   /*  730 */,    Long.fromString("AAE128B0DC93537C", 16)   /*  731 */,
    Long.fromString("3A493DA0EE4B29AE", 16)   /*  732 */,    Long.fromString("B5DF6B2C416895D7", 16)   /*  733 */,
    Long.fromString("FCABBD25122D7F37", 16)   /*  734 */,    Long.fromString("70810B58105DC4B1", 16)   /*  735 */,
    Long.fromString("E10FDD37F7882A90", 16)   /*  736 */,    Long.fromString("524DCAB5518A3F5C", 16)   /*  737 */,
    Long.fromString("3C9E85878451255B", 16)   /*  738 */,    Long.fromString("4029828119BD34E2", 16)   /*  739 */,
    Long.fromString("74A05B6F5D3CECCB", 16)   /*  740 */,    Long.fromString("B610021542E13ECA", 16)   /*  741 */,
    Long.fromString("0FF979D12F59E2AC", 16)   /*  742 */,    Long.fromString("6037DA27E4F9CC50", 16)   /*  743 */,
    Long.fromString("5E92975A0DF1847D", 16)   /*  744 */,    Long.fromString("D66DE190D3E623FE", 16)   /*  745 */,
    Long.fromString("5032D6B87B568048", 16)   /*  746 */,    Long.fromString("9A36B7CE8235216E", 16)   /*  747 */,
    Long.fromString("80272A7A24F64B4A", 16)   /*  748 */,    Long.fromString("93EFED8B8C6916F7", 16)   /*  749 */,
    Long.fromString("37DDBFF44CCE1555", 16)   /*  750 */,    Long.fromString("4B95DB5D4B99BD25", 16)   /*  751 */,
    Long.fromString("92D3FDA169812FC0", 16)   /*  752 */,    Long.fromString("FB1A4A9A90660BB6", 16)   /*  753 */,
    Long.fromString("730C196946A4B9B2", 16)   /*  754 */,    Long.fromString("81E289AA7F49DA68", 16)   /*  755 */,
    Long.fromString("64669A0F83B1A05F", 16)   /*  756 */,    Long.fromString("27B3FF7D9644F48B", 16)   /*  757 */,
    Long.fromString("CC6B615C8DB675B3", 16)   /*  758 */,    Long.fromString("674F20B9BCEBBE95", 16)   /*  759 */,
    Long.fromString("6F31238275655982", 16)   /*  760 */,    Long.fromString("5AE488713E45CF05", 16)   /*  761 */,
    Long.fromString("BF619F9954C21157", 16)   /*  762 */,    Long.fromString("EABAC46040A8EAE9", 16)   /*  763 */,
    Long.fromString("454C6FE9F2C0C1CD", 16)   /*  764 */,    Long.fromString("419CF6496412691C", 16)   /*  765 */,
    Long.fromString("D3DC3BEF265B0F70", 16)   /*  766 */,    Long.fromString("6D0E60F5C3578A9E", 16)   /*  767 */,
];

const t4 = [
    Long.fromString("5B0E608526323C55", 16)   /*  768 */,    Long.fromString("1A46C1A9FA1B59F5", 16)   /*  769 */,
    Long.fromString("A9E245A17C4C8FFA", 16)   /*  770 */,    Long.fromString("65CA5159DB2955D7", 16)   /*  771 */,
    Long.fromString("05DB0A76CE35AFC2", 16)   /*  772 */,    Long.fromString("81EAC77EA9113D45", 16)   /*  773 */,
    Long.fromString("528EF88AB6AC0A0D", 16)   /*  774 */,    Long.fromString("A09EA253597BE3FF", 16)   /*  775 */,
    Long.fromString("430DDFB3AC48CD56", 16)   /*  776 */,    Long.fromString("C4B3A67AF45CE46F", 16)   /*  777 */,
    Long.fromString("4ECECFD8FBE2D05E", 16)   /*  778 */,    Long.fromString("3EF56F10B39935F0", 16)   /*  779 */,
    Long.fromString("0B22D6829CD619C6", 16)   /*  780 */,    Long.fromString("17FD460A74DF2069", 16)   /*  781 */,
    Long.fromString("6CF8CC8E8510ED40", 16)   /*  782 */,    Long.fromString("D6C824BF3A6ECAA7", 16)   /*  783 */,
    Long.fromString("61243D581A817049", 16)   /*  784 */,    Long.fromString("048BACB6BBC163A2", 16)   /*  785 */,
    Long.fromString("D9A38AC27D44CC32", 16)   /*  786 */,    Long.fromString("7FDDFF5BAAF410AB", 16)   /*  787 */,
    Long.fromString("AD6D495AA804824B", 16)   /*  788 */,    Long.fromString("E1A6A74F2D8C9F94", 16)   /*  789 */,
    Long.fromString("D4F7851235DEE8E3", 16)   /*  790 */,    Long.fromString("FD4B7F886540D893", 16)   /*  791 */,
    Long.fromString("247C20042AA4BFDA", 16)   /*  792 */,    Long.fromString("096EA1C517D1327C", 16)   /*  793 */,
    Long.fromString("D56966B4361A6685", 16)   /*  794 */,    Long.fromString("277DA5C31221057D", 16)   /*  795 */,
    Long.fromString("94D59893A43ACFF7", 16)   /*  796 */,    Long.fromString("64F0C51CCDC02281", 16)   /*  797 */,
    Long.fromString("3D33BCC4FF6189DB", 16)   /*  798 */,    Long.fromString("E005CB184CE66AF1", 16)   /*  799 */,
    Long.fromString("FF5CCD1D1DB99BEA", 16)   /*  800 */,    Long.fromString("B0B854A7FE42980F", 16)   /*  801 */,
    Long.fromString("7BD46A6A718D4B9F", 16)   /*  802 */,    Long.fromString("D10FA8CC22A5FD8C", 16)   /*  803 */,
    Long.fromString("D31484952BE4BD31", 16)   /*  804 */,    Long.fromString("C7FA975FCB243847", 16)   /*  805 */,
    Long.fromString("4886ED1E5846C407", 16)   /*  806 */,    Long.fromString("28CDDB791EB70B04", 16)   /*  807 */,
    Long.fromString("C2B00BE2F573417F", 16)   /*  808 */,    Long.fromString("5C9590452180F877", 16)   /*  809 */,
    Long.fromString("7A6BDDFFF370EB00", 16)   /*  810 */,    Long.fromString("CE509E38D6D9D6A4", 16)   /*  811 */,
    Long.fromString("EBEB0F00647FA702", 16)   /*  812 */,    Long.fromString("1DCC06CF76606F06", 16)   /*  813 */,
    Long.fromString("E4D9F28BA286FF0A", 16)   /*  814 */,    Long.fromString("D85A305DC918C262", 16)   /*  815 */,
    Long.fromString("475B1D8732225F54", 16)   /*  816 */,    Long.fromString("2D4FB51668CCB5FE", 16)   /*  817 */,
    Long.fromString("A679B9D9D72BBA20", 16)   /*  818 */,    Long.fromString("53841C0D912D43A5", 16)   /*  819 */,
    Long.fromString("3B7EAA48BF12A4E8", 16)   /*  820 */,    Long.fromString("781E0E47F22F1DDF", 16)   /*  821 */,
    Long.fromString("EFF20CE60AB50973", 16)   /*  822 */,    Long.fromString("20D261D19DFFB742", 16)   /*  823 */,
    Long.fromString("16A12B03062A2E39", 16)   /*  824 */,    Long.fromString("1960EB2239650495", 16)   /*  825 */,
    Long.fromString("251C16FED50EB8B8", 16)   /*  826 */,    Long.fromString("9AC0C330F826016E", 16)   /*  827 */,
    Long.fromString("ED152665953E7671", 16)   /*  828 */,    Long.fromString("02D63194A6369570", 16)   /*  829 */,
    Long.fromString("5074F08394B1C987", 16)   /*  830 */,    Long.fromString("70BA598C90B25CE1", 16)   /*  831 */,
    Long.fromString("794A15810B9742F6", 16)   /*  832 */,    Long.fromString("0D5925E9FCAF8C6C", 16)   /*  833 */,
    Long.fromString("3067716CD868744E", 16)   /*  834 */,    Long.fromString("910AB077E8D7731B", 16)   /*  835 */,
    Long.fromString("6A61BBDB5AC42F61", 16)   /*  836 */,    Long.fromString("93513EFBF0851567", 16)   /*  837 */,
    Long.fromString("F494724B9E83E9D5", 16)   /*  838 */,    Long.fromString("E887E1985C09648D", 16)   /*  839 */,
    Long.fromString("34B1D3C675370CFD", 16)   /*  840 */,    Long.fromString("DC35E433BC0D255D", 16)   /*  841 */,
    Long.fromString("D0AAB84234131BE0", 16)   /*  842 */,    Long.fromString("08042A50B48B7EAF", 16)   /*  843 */,
    Long.fromString("9997C4EE44A3AB35", 16)   /*  844 */,    Long.fromString("829A7B49201799D0", 16)   /*  845 */,
    Long.fromString("263B8307B7C54441", 16)   /*  846 */,    Long.fromString("752F95F4FD6A6CA6", 16)   /*  847 */,
    Long.fromString("927217402C08C6E5", 16)   /*  848 */,    Long.fromString("2A8AB754A795D9EE", 16)   /*  849 */,
    Long.fromString("A442F7552F72943D", 16)   /*  850 */,    Long.fromString("2C31334E19781208", 16)   /*  851 */,
    Long.fromString("4FA98D7CEAEE6291", 16)   /*  852 */,    Long.fromString("55C3862F665DB309", 16)   /*  853 */,
    Long.fromString("BD0610175D53B1F3", 16)   /*  854 */,    Long.fromString("46FE6CB840413F27", 16)   /*  855 */,
    Long.fromString("3FE03792DF0CFA59", 16)   /*  856 */,    Long.fromString("CFE700372EB85E8F", 16)   /*  857 */,
    Long.fromString("A7BE29E7ADBCE118", 16)   /*  858 */,    Long.fromString("E544EE5CDE8431DD", 16)   /*  859 */,
    Long.fromString("8A781B1B41F1873E", 16)   /*  860 */,    Long.fromString("A5C94C78A0D2F0E7", 16)   /*  861 */,
    Long.fromString("39412E2877B60728", 16)   /*  862 */,    Long.fromString("A1265EF3AFC9A62C", 16)   /*  863 */,
    Long.fromString("BCC2770C6A2506C5", 16)   /*  864 */,    Long.fromString("3AB66DD5DCE1CE12", 16)   /*  865 */,
    Long.fromString("E65499D04A675B37", 16)   /*  866 */,    Long.fromString("7D8F523481BFD216", 16)   /*  867 */,
    Long.fromString("0F6F64FCEC15F389", 16)   /*  868 */,    Long.fromString("74EFBE618B5B13C8", 16)   /*  869 */,
    Long.fromString("ACDC82B714273E1D", 16)   /*  870 */,    Long.fromString("DD40BFE003199D17", 16)   /*  871 */,
    Long.fromString("37E99257E7E061F8", 16)   /*  872 */,    Long.fromString("FA52626904775AAA", 16)   /*  873 */,
    Long.fromString("8BBBF63A463D56F9", 16)   /*  874 */,    Long.fromString("F0013F1543A26E64", 16)   /*  875 */,
    Long.fromString("A8307E9F879EC898", 16)   /*  876 */,    Long.fromString("CC4C27A4150177CC", 16)   /*  877 */,
    Long.fromString("1B432F2CCA1D3348", 16)   /*  878 */,    Long.fromString("DE1D1F8F9F6FA013", 16)   /*  879 */,
    Long.fromString("606602A047A7DDD6", 16)   /*  880 */,    Long.fromString("D237AB64CC1CB2C7", 16)   /*  881 */,
    Long.fromString("9B938E7225FCD1D3", 16)   /*  882 */,    Long.fromString("EC4E03708E0FF476", 16)   /*  883 */,
    Long.fromString("FEB2FBDA3D03C12D", 16)   /*  884 */,    Long.fromString("AE0BCED2EE43889A", 16)   /*  885 */,
    Long.fromString("22CB8923EBFB4F43", 16)   /*  886 */,    Long.fromString("69360D013CF7396D", 16)   /*  887 */,
    Long.fromString("855E3602D2D4E022", 16)   /*  888 */,    Long.fromString("073805BAD01F784C", 16)   /*  889 */,
    Long.fromString("33E17A133852F546", 16)   /*  890 */,    Long.fromString("DF4874058AC7B638", 16)   /*  891 */,
    Long.fromString("BA92B29C678AA14A", 16)   /*  892 */,    Long.fromString("0CE89FC76CFAADCD", 16)   /*  893 */,
    Long.fromString("5F9D4E0908339E34", 16)   /*  894 */,    Long.fromString("F1AFE9291F5923B9", 16)   /*  895 */,
    Long.fromString("6E3480F60F4A265F", 16)   /*  896 */,    Long.fromString("EEBF3A2AB29B841C", 16)   /*  897 */,
    Long.fromString("E21938A88F91B4AD", 16)   /*  898 */,    Long.fromString("57DFEFF845C6D3C3", 16)   /*  899 */,
    Long.fromString("2F006B0BF62CAAF2", 16)   /*  900 */,    Long.fromString("62F479EF6F75EE78", 16)   /*  901 */,
    Long.fromString("11A55AD41C8916A9", 16)   /*  902 */,    Long.fromString("F229D29084FED453", 16)   /*  903 */,
    Long.fromString("42F1C27B16B000E6", 16)   /*  904 */,    Long.fromString("2B1F76749823C074", 16)   /*  905 */,
    Long.fromString("4B76ECA3C2745360", 16)   /*  906 */,    Long.fromString("8C98F463B91691BD", 16)   /*  907 */,
    Long.fromString("14BCC93CF1ADE66A", 16)   /*  908 */,    Long.fromString("8885213E6D458397", 16)   /*  909 */,
    Long.fromString("8E177DF0274D4711", 16)   /*  910 */,    Long.fromString("B49B73B5503F2951", 16)   /*  911 */,
    Long.fromString("10168168C3F96B6B", 16)   /*  912 */,    Long.fromString("0E3D963B63CAB0AE", 16)   /*  913 */,
    Long.fromString("8DFC4B5655A1DB14", 16)   /*  914 */,    Long.fromString("F789F1356E14DE5C", 16)   /*  915 */,
    Long.fromString("683E68AF4E51DAC1", 16)   /*  916 */,    Long.fromString("C9A84F9D8D4B0FD9", 16)   /*  917 */,
    Long.fromString("3691E03F52A0F9D1", 16)   /*  918 */,    Long.fromString("5ED86E46E1878E80", 16)   /*  919 */,
    Long.fromString("3C711A0E99D07150", 16)   /*  920 */,    Long.fromString("5A0865B20C4E9310", 16)   /*  921 */,
    Long.fromString("56FBFC1FE4F0682E", 16)   /*  922 */,    Long.fromString("EA8D5DE3105EDF9B", 16)   /*  923 */,
    Long.fromString("71ABFDB12379187A", 16)   /*  924 */,    Long.fromString("2EB99DE1BEE77B9C", 16)   /*  925 */,
    Long.fromString("21ECC0EA33CF4523", 16)   /*  926 */,    Long.fromString("59A4D7521805C7A1", 16)   /*  927 */,
    Long.fromString("3896F5EB56AE7C72", 16)   /*  928 */,    Long.fromString("AA638F3DB18F75DC", 16)   /*  929 */,
    Long.fromString("9F39358DABE9808E", 16)   /*  930 */,    Long.fromString("B7DEFA91C00B72AC", 16)   /*  931 */,
    Long.fromString("6B5541FD62492D92", 16)   /*  932 */,    Long.fromString("6DC6DEE8F92E4D5B", 16)   /*  933 */,
    Long.fromString("353F57ABC4BEEA7E", 16)   /*  934 */,    Long.fromString("735769D6DA5690CE", 16)   /*  935 */,
    Long.fromString("0A234AA642391484", 16)   /*  936 */,    Long.fromString("F6F9508028F80D9D", 16)   /*  937 */,
    Long.fromString("B8E319A27AB3F215", 16)   /*  938 */,    Long.fromString("31AD9C1151341A4D", 16)   /*  939 */,
    Long.fromString("773C22A57BEF5805", 16)   /*  940 */,    Long.fromString("45C7561A07968633", 16)   /*  941 */,
    Long.fromString("F913DA9E249DBE36", 16)   /*  942 */,    Long.fromString("DA652D9B78A64C68", 16)   /*  943 */,
    Long.fromString("4C27A97F3BC334EF", 16)   /*  944 */,    Long.fromString("76621220E66B17F4", 16)   /*  945 */,
    Long.fromString("967743899ACD7D0B", 16)   /*  946 */,    Long.fromString("F3EE5BCAE0ED6782", 16)   /*  947 */,
    Long.fromString("409F753600C879FC", 16)   /*  948 */,    Long.fromString("06D09A39B5926DB6", 16)   /*  949 */,
    Long.fromString("6F83AEB0317AC588", 16)   /*  950 */,    Long.fromString("01E6CA4A86381F21", 16)   /*  951 */,
    Long.fromString("66FF3462D19F3025", 16)   /*  952 */,    Long.fromString("72207C24DDFD3BFB", 16)   /*  953 */,
    Long.fromString("4AF6B6D3E2ECE2EB", 16)   /*  954 */,    Long.fromString("9C994DBEC7EA08DE", 16)   /*  955 */,
    Long.fromString("49ACE597B09A8BC4", 16)   /*  956 */,    Long.fromString("B38C4766CF0797BA", 16)   /*  957 */,
    Long.fromString("131B9373C57C2A75", 16)   /*  958 */,    Long.fromString("B1822CCE61931E58", 16)   /*  959 */,
    Long.fromString("9D7555B909BA1C0C", 16)   /*  960 */,    Long.fromString("127FAFDD937D11D2", 16)   /*  961 */,
    Long.fromString("29DA3BADC66D92E4", 16)   /*  962 */,    Long.fromString("A2C1D57154C2ECBC", 16)   /*  963 */,
    Long.fromString("58C5134D82F6FE24", 16)   /*  964 */,    Long.fromString("1C3AE3515B62274F", 16)   /*  965 */,
    Long.fromString("E907C82E01CB8126", 16)   /*  966 */,    Long.fromString("F8ED091913E37FCB", 16)   /*  967 */,
    Long.fromString("3249D8F9C80046C9", 16)   /*  968 */,    Long.fromString("80CF9BEDE388FB63", 16)   /*  969 */,
    Long.fromString("1881539A116CF19E", 16)   /*  970 */,    Long.fromString("5103F3F76BD52457", 16)   /*  971 */,
    Long.fromString("15B7E6F5AE47F7A8", 16)   /*  972 */,    Long.fromString("DBD7C6DED47E9CCF", 16)   /*  973 */,
    Long.fromString("44E55C410228BB1A", 16)   /*  974 */,    Long.fromString("B647D4255EDB4E99", 16)   /*  975 */,
    Long.fromString("5D11882BB8AAFC30", 16)   /*  976 */,    Long.fromString("F5098BBB29D3212A", 16)   /*  977 */,
    Long.fromString("8FB5EA14E90296B3", 16)   /*  978 */,    Long.fromString("677B942157DD025A", 16)   /*  979 */,
    Long.fromString("FB58E7C0A390ACB5", 16)   /*  980 */,    Long.fromString("89D3674C83BD4A01", 16)   /*  981 */,
    Long.fromString("9E2DA4DF4BF3B93B", 16)   /*  982 */,    Long.fromString("FCC41E328CAB4829", 16)   /*  983 */,
    Long.fromString("03F38C96BA582C52", 16)   /*  984 */,    Long.fromString("CAD1BDBD7FD85DB2", 16)   /*  985 */,
    Long.fromString("BBB442C16082AE83", 16)   /*  986 */,    Long.fromString("B95FE86BA5DA9AB0", 16)   /*  987 */,
    Long.fromString("B22E04673771A93F", 16)   /*  988 */,    Long.fromString("845358C9493152D8", 16)   /*  989 */,
    Long.fromString("BE2A488697B4541E", 16)   /*  990 */,    Long.fromString("95A2DC2DD38E6966", 16)   /*  991 */,
    Long.fromString("C02C11AC923C852B", 16)   /*  992 */,    Long.fromString("2388B1990DF2A87B", 16)   /*  993 */,
    Long.fromString("7C8008FA1B4F37BE", 16)   /*  994 */,    Long.fromString("1F70D0C84D54E503", 16)   /*  995 */,
    Long.fromString("5490ADEC7ECE57D4", 16)   /*  996 */,    Long.fromString("002B3C27D9063A3A", 16)   /*  997 */,
    Long.fromString("7EAEA3848030A2BF", 16)   /*  998 */,    Long.fromString("C602326DED2003C0", 16)   /*  999 */,
    Long.fromString("83A7287D69A94086", 16)   /* 1000 */,    Long.fromString("C57A5FCB30F57A8A", 16)   /* 1001 */,
    Long.fromString("B56844E479EBE779", 16)   /* 1002 */,    Long.fromString("A373B40F05DCBCE9", 16)   /* 1003 */,
    Long.fromString("D71A786E88570EE2", 16)   /* 1004 */,    Long.fromString("879CBACDBDE8F6A0", 16)   /* 1005 */,
    Long.fromString("976AD1BCC164A32F", 16)   /* 1006 */,    Long.fromString("AB21E25E9666D78B", 16)   /* 1007 */,
    Long.fromString("901063AAE5E5C33C", 16)   /* 1008 */,    Long.fromString("9818B34448698D90", 16)   /* 1009 */,
    Long.fromString("E36487AE3E1E8ABB", 16)   /* 1010 */,    Long.fromString("AFBDF931893BDCB4", 16)   /* 1011 */,
    Long.fromString("6345A0DC5FBBD519", 16)   /* 1012 */,    Long.fromString("8628FE269B9465CA", 16)   /* 1013 */,
    Long.fromString("1E5D01603F9C51EC", 16)   /* 1014 */,    Long.fromString("4DE44006A15049B7", 16)   /* 1015 */,
    Long.fromString("BF6C70E5F776CBB1", 16)   /* 1016 */,    Long.fromString("411218F2EF552BED", 16)   /* 1017 */,
    Long.fromString("CB0C0708705A36A3", 16)   /* 1018 */,    Long.fromString("E74D14754F986044", 16)   /* 1019 */,
    Long.fromString("CD56D9430EA8280E", 16)   /* 1020 */,    Long.fromString("C12591D7535F5065", 16)   /* 1021 */,
    Long.fromString("C83223F1720AEF96", 16)   /* 1022 */,    Long.fromString("C3A0396F7363A51F", 16)   /* 1023 */
];


