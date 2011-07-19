require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  Skein = require('hash/skein').Skein,
  crypto = require('crypto'),
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "Skein test vectors":function(test) {
    var vectors = parseNonMac(nonMacString);
    
    // for(var i = 0; i < 1; i++) {
    for(var i = 0; i < vectors.length; i++) {
      var vector = vectors[i];
      // Unpack test vector
      var stateSize = vector.stateSize;
      var hashBitLength = vector.hashBitLength;
      var msgLength = vector.msgLength;
      var message = vector.message.length >= 2 ? util.hexStringToBinaryArray(vector.message) : [];
      var digest = util.hexStringToBinaryArray(vector.result);
  
      if(msgLength % 8 == 0) {
        var skein = new Skein(stateSize, hashBitLength);
        skein.update(message);        

        var finalDigest = new Array(skein.getDigestSize());
        test.equal(skein.getDigestSize(), skein.doFinal(finalDigest, 0));
        test.deepEqual(digest, finalDigest);
      } else {
        var skein = new Skein(stateSize, hashBitLength);
        skein.updateBits(message, msgLength);

        var finalDigest = new Array(skein.getDigestSize());
        test.equal(skein.getDigestSize(), skein.doFinal(finalDigest, 0));
        test.deepEqual(digest, finalDigest);        
      }
    }
    
    test.done();
  }  
});

var parseNonMac = function(text) {
  var vectors = [];
  var lines = text.split(/\n/);
  while(lines.length > 1) {
    // Get rid of empty string
    lines.shift();
    // Split out the data
    var defString = lines.shift();
    var _1 = parseInt(defString.match(/Skein\-[0-9]*/g)[0].split(/\-/)[1].trim());
    var _2 = parseInt(defString.match(/[0-9]*\-bit/g)[0].split(/\-/)[0].trim());
    var _3 = parseInt(defString.match(/msgLen \= [ |0-9]*/g)[0].split(/=/)[1].trim());
    var _4 = defString.match(/data \= \'[a-z]*\'/g)[0].split(/=/)[1].trim().replace(/\'/g, '');
    // Get message
    lines.shift();
    lines.shift();
    // line
    var line = lines.shift();
    var messagedata = "";
    var result = "";

    while(line.match(/Result/) == null) {
      if(line.match(/\(none\)/) != null) {
        line = lines.shift();
        break
      };
      // If we have bytes let's clean them up and add ot the messagedata
      messagedata = messagedata + line.replace(/ */g, '');
      line = lines.shift();
    }

    // Skip to next message
    // line = lines.shift();
    line = lines.shift();

    while(line.match(/--------------------------------/) == null) {
      result = result + line.replace(/ */g, '');    
      line = lines.shift();
    }
    
    vectors.push({stateSize:_1, hashBitLength:_2, msgLength:_3, message:messagedata, result:result});

    // debug("----------------------------------------------------------------------------------")
    // debug(_1)
    // debug(_2)
    // debug(_3)
    // debug(_4)
    // debug("messagedata = " + messagedata)
    // debug("result = " + result)    
  }
  
  return vectors;
}

var nonMacString = "\n" +
      ":Skein-256:   256-bit hash, msgLen =     0 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     C8 87 70 87  DA 56 E0 72  87 0D AA 84  3F 17 6E 94\n" +
      "     53 11 59 29  09 4C 3A 40  C4 63 A1 96  C2 9B F7 BA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     1 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     52 D2 B5 FF  C2 96 6C 06  BA 7B B0 CC  2B AB BC 93\n" +
      "     5E 99 14 64  87 FB 36 1A  23 98 30 D4  D6 88 C9 88\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     2 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     86 66 FA 24  37 50 BE 24  C8 45 CF A1  66 41 91 94\n" +
      "     DC 6B 1E 9C  91 23 0A 16  FF E4 04 B6  8D 04 19 7C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     3 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     1C 87 FD F9  4B D6 05 DA  4C DF BC BA  94 94 44 94\n" +
      "     C5 CC 90 3D  86 75 B7 AF  A1 8A 03 29  D6 CD 39 43\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     4 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     AF 17 85 F0  2B 2B 19 43  EA 91 E7 EC  29 51 8C 4E\n" +
      "     51 62 A0 63  D5 58 B2 0C  44 D2 6B F2  7C AD CB A4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     5 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     63 68 D2 1E  D9 C4 5B AB  EA 37 33 1A  92 66 47 27\n" +
      "     0A E3 1A 78  BD 97 A0 70  D0 D2 0E 56  7A D0 EB 23\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     6 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     79 70 60 AC  48 1D FE 00  98 46 B1 9C  DA B4 29 6F\n" +
      "     B6 7C 8C EA  AB 7F 64 49  46 4C 72 DD  08 1E D2 4D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     7 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     CF FC CE 54  EA 30 F1 13  99 73 A0 63  89 C9 7E 19\n" +
      "     F9 CC 8A B6  91 14 9E 16  A6 B2 A1 E6  D8 02 CA D0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     8 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     34 E2 B6 5B  F0 BE 66 7C  A5 DE BA 82  C3 7C B2 53\n" +
      "     EB 9F 84 74  F3 42 6B A6  22 A2 52 19  FD 18 24 33\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     9 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     FD DD 63 1B  A8 79 6C 51  A1 F3 2D A4  E4 BB 7D 3F\n" +
      "     B2 AE BC 93  A5 1D 8D DA  AC F1 E3 AC  6C 7A DE 5C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    10 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     A4 60 86 A6  D2 56 69 71  3B D5 80 B0  75 25 D2 E7\n" +
      "     DE B8 6E D3  05 76 F7 8D  60 98 51 B7  62 F6 65 DC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    32 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00\n" +
      "Result:\n" +
      "     69 60 42 6D  85 F4 F1 0D  AA 23 21 3D  E5 AD D2 10\n" +
      "     1F 4C 1B 79  0B 53 0B F7  AA 66 F0 93  0B B6 B9 06\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    64 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     76 E4 8C FD  E0 17 7E C9  B1 18 E7 DF  8F 0C 63 E6\n" +
      "     60 39 B7 69  94 64 6D 32  7F 7A DB 6C  EE A4 D0 E3\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   128 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     73 EC 78 07  DD E9 87 D6  96 00 D1 38  25 5E 4A F0\n" +
      "     58 5C 6C A9  0A 6C 7A 4A  DF 8B C0 25  A2 FA C3 94\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   192 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     CB C2 6D E4  C8 21 2B 6C  7B C4 E0 CA  43 79 0A 55\n" +
      "     FB 19 A6 E4  7C 64 A7 7D  8F 8F B3 24  DB 12 68 41\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   255 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     4A 90 C6 FF  EB 2D C6 60  29 9C A6 A5  96 0B DB 97\n" +
      "     01 16 B5 A3  30 7F E4 75  A1 24 84 6E  85 11 71 12\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   256 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     0F ED 47 EF  57 B6 13 79  E4 A4 06 A8  FA 3F 8F B9\n" +
      "     D3 80 DA FA  DA 31 8F F1  49 1D 11 08  D6 60 0A 50\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   257 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     3E AE A9 96  FA D9 5B 60  32 65 4D 6C  A9 3A C3 45\n" +
      "     0B ED 8C 75  4C D8 00 04  60 A2 87 6E  34 E5 2F A7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   384 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     FB F5 67 B1  42 34 F1 40  C0 64 54 EB  26 B8 39 68\n" +
      "     DF 8A 8C FC  CE 69 AF DE  33 A2 32 EB  22 26 13 7C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   511 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     89 93 81 0B  15 FA 33 2F  C3 33 AA 2E  A8 00 02 19\n" +
      "     BC 77 7A E5  16 58 EC 3A  3A 72 E9 90  8A 39 E6 78\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   512 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     3E 0C A2 9E  48 63 E8 BE  4D 9F 28 77  7A 7F DC 67\n" +
      "     60 32 C4 D9  F6 90 4B 1C  B6 AA BB 02  9F 33 74 1A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   513 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     A0 CE D7 06  DE 22 FA 8C  B8 46 8C D5  8F 4D 89 BD\n" +
      "     14 1C F9 42  E3 03 79 F2  52 82 14 B9  AB 0A 4F 06\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   768 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     8B 09 13 FE  58 3A F8 38  E7 45 EC 90  11 97 84 82\n" +
      "     FB 83 A3 C5  8E DA 5F A0  4F F7 08 32  B1 AC 63 9A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1023 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     59 2C 4A AF  0B F1 F4 63  7D B9 CA FA  E2 83 F5 2E\n" +
      "     73 41 E5 62  ED 0F 99 33  9D 76 72 45  A8 00 0E 41\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   160-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     2E 69 3A A8  CA FB 42 D9  0C 80 8F 7D  2F B6 C9 25\n" +
      "     DF 61 82 75\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   224-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     F4 B5 2F CE  D0 C8 8E 95  A3 CA 67 B2  D2 D8 D8 D4\n" +
      "     D2 DD 16 CA  FC 0D B7 AE  CE 57 0F 53\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     35 DA 44 B9  1B FB 02 0E  6E 85 59 2E  33 10 A6 E6\n" +
      "     D8 93 9A 64  C7 78 91 30  03 A6 1B C1  35 83 ED AF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   384-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     20 ED 53 61  58 C5 E9 B3  FC 04 E4 C4  4B 00 95 74\n" +
      "     4B 14 4F 11  B0 A7 31 21  3A 14 34 02  C8 FD A1 D6\n" +
      "     04 6F C3 78  4C A3 D4 6F  3F 2A 9F CC  AC B9 9B 35\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   512-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     91 8A 1B 6D  20 01 5D 0B  F5 3C F4 FD  D3 9E 28 D8\n" +
      "     BC 55 04 A9  6C 1D 31 0A  D5 AD B1 5D  CD DE A2 70\n" +
      "     18 4F 94 67  45 1C D9 7B  C6 24 D3 08  83 A0 06 33\n" +
      "     64 57 81 5A  88 A9 FE B4  49 46 0E 4B  42 D9 66 AC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1024-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     73 F2 80 5C  D8 AA CD 38  CE 95 65 7D  FD C1 F9 2C\n" +
      "     FF C6 47 12  23 8D 54 52  0C 43 61 B2  FE 95 70 91\n" +
      "     40 2E 40 21  D8 2E 55 2F  AC 5E 01 5E  79 3C 4B D2\n" +
      "     34 BC 24 83  09 F2 85 CF  21 45 56 AB  92 F3 DD 56\n" +
      "     30 8E 3A D5  ED 9B 11 26  5F D5 70 8A  53 E2 45 64\n" +
      "     76 4F 79 CC  39 E8 BF E2  AC 86 7D 36  84 F2 BF 8E\n" +
      "     23 7D 98 7E  51 50 5B FB  6D D7 46 83  51 76 B6 D7\n" +
      "     69 63 F0 A6  2D 4E 57 F6  49 C0 D1 00  06 7D DD FB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   264-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     7F 3C 24 0F  C8 FA 57 33  7C BC 0D 36  91 19 C0 AF\n" +
      "     71 28 2A 53  BD B5 81 D0  A2 D4 3A D3  36 59 56 4F\n" +
      "     67\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   520-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     32 5D 9D 81  74 85 16 23  C9 AB AA D6  AD 6A 61 24\n" +
      "     EB 21 E0 4E  F0 40 B4 39  B3 E9 E9 25  B9 91 45 11\n" +
      "     2D AC 7A CB  D3 35 BA 83  34 90 6B 63  CE 54 00 37\n" +
      "     C4 5E 4F 65  04 A3 5C 94  27 4D 03 F8  04 9D 59 7F\n" +
      "     D9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1032-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     C3 5A 32 B2  CD 5C C7 AA  8B 72 4F 41  A5 E0 F7 FE\n" +
      "     A4 5C D5 18  F4 E3 99 1C  AC A5 39 65  5D 50 39 60\n" +
      "     38 60 A1 FA  48 CE D6 73  8C 25 A9 C2  46 68 2D 18\n" +
      "     F1 FC 8E 18  98 58 CA 6C  8F CE AA 51  FE 73 2A 36\n" +
      "     84 86 88 5A  33 13 D9 84  DB D9 75 D1  38 95 11 69\n" +
      "     E1 3A 16 3A  C0 2E 6A 36  7C 1C 9E 71  29 D2 E4 04\n" +
      "     29 BB 49 3A  F1 FB 08 FF  98 14 B1 ED  4B FA 91 90\n" +
      "     09 4F D8 98  FC 02 6E 99  35 29 79 96  23 89 AB EA\n" +
      "     B7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  2056-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     6D A9 85 3C  DB 81 A3 34  21 2F FD 6A  B4 1D 2C 38\n" +
      "     3F E1 F8 54  30 C2 B0 E3  4E C1 A7 D9  24 11 4E A3\n" +
      "     3D 39 48 79  39 F2 03 38  2B 61 BC 56  48 4D 0D 52\n" +
      "     EC C9 DB E9  7F 12 6F EF  21 EE 56 D6  57 20 AD F5\n" +
      "     BF 10 1D 4F  F4 E9 F4 AB  A6 F4 EC 35  95 C8 0E 28\n" +
      "     AB C8 2D 46  BE B2 B9 31  FE 36 06 1B  B6 BA CE 33\n" +
      "     B8 EA B0 73  98 D6 48 5D  30 DB 9E 70  DB E9 A5 F5\n" +
      "     D4 42 CD 1D  D3 CF 8D 98  37 EC 6A 28  71 74 96 93\n" +
      "     C1 43 AB 0C  E9 2A D5 27  6C 20 44 B0  DC 92 2F 55\n" +
      "     57 2C F4 66  61 F0 82 41  38 DF A8 A2  48 7F 0D 8D\n" +
      "     D8 13 FB BE  60 2E 20 BF  25 35 A1 B4  ED 66 B5 14\n" +
      "     9F 33 82 0B  F0 E5 EA 74  23 FA 33 B2  E4 B1 92 46\n" +
      "     8D BE 56 AD  DE 36 EA 55  D0 DB 35 E3  26 96 80 68\n" +
      "     BA 3B 28 34  43 AE C2 AC  8F 5F 1B CF  D2 81 7D 77\n" +
      "     9F 64 9E 6A  81 D4 2C 79  46 AC D2 33  C5 44 12 79\n" +
      "     C9 85 F3 BE  40 ED F9 4B  FC E5 92 0D  C4 D3 5C D2\n" +
      "     9F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1025 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     CC 52 B7 C8  FF B1 69 96  98 A7 30 DA  A0 77 D4 7B\n" +
      "     6E 6A 29 FB  B2 64 67 E0  9F EE 07 D5  F8 8A CA 45\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2047 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     9D 11 36 9D  8B B6 77 2A  50 55 01 25  BB 37 A5 12\n" +
      "     D3 94 10 98  8A 78 03 84  C2 8B 49 E0  63 38 82 CA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2048 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     E0 0F A9 CB  56 04 6C C2  D2 55 6E 2A  DF 24 E9 2F\n" +
      "     68 1A E3 FE  9B D8 C2 10  37 80 C2 99  38 D6 4F FE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2049 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     29 74 00 18  60 D6 21 2B  E3 AD 89 4F  31 B2 D8 16\n" +
      "     01 98 EE 7E  B0 EC AE CB  F9 C4 98 BB  DF 64 1D B0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     0 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     BC 5B 4C 50  92 55 19 C2  90 CC 63 42  77 AE 3D 62\n" +
      "     57 21 23 95  CB A7 33 BB  AD 37 A4 AF  0F A0 6A F4\n" +
      "     1F CA 79 03  D0 65 64 FE  A7 A2 D3 73  0D BD B8 0C\n" +
      "     1F 85 56 2D  FC C0 70 33  4E A4 D1 D9  E7 2C BA 7A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     1 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     BF 96 B3 5C  EC AF C8 AD  25 AC 72 07  E9 0E F2 79\n" +
      "     FE 99 BE 45  94 AE 99 6F  72 69 68 C4  B7 99 01 8A\n" +
      "     24 8D 80 15  29 52 C4 C3  15 89 77 6C  36 7E 7B 61\n" +
      "     53 DC 0D BD  F1 B4 79 D5  32 98 A6 32  8A A0 3F DB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     2 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     97 3A A7 7A  56 2C A7 1B  D5 40 59 8B  1A 88 B8 03\n" +
      "     74 30 9B CA  89 CD F9 79  EE 4A D9 20  23 E4 9D 35\n" +
      "     D0 EA D2 EE  8D F7 51 C3  62 42 BA 14  79 2C E7 FC\n" +
      "     AB 91 DD D1  CA 8B D1 18  A3 57 1D 65  81 14 11 CD\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     3 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     53 12 DD 38  A2 7B 52 7E  0F A8 14 7A  54 19 A8 6B\n" +
      "     CF A0 09 B9  8E 0D 49 D2  A1 85 BC D7  87 33 E0 B4\n" +
      "     2F FC 06 16  24 56 A7 CE  41 3C 34 41  82 64 F8 B0\n" +
      "     E4 A5 10 BC  BD 80 A8 AA  DA 66 89 BB  C5 F8 0B E8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     4 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     D8 8A 69 3B  6C 26 04 9D  ED 03 51 91  91 00 4B 9A\n" +
      "     AB E3 34 28  ED 96 93 59  90 4E CB 0B  DA 03 FF D3\n" +
      "     F5 F8 C3 94  45 98 20 5A  EC 25 79 32  DD 77 33 11\n" +
      "     A9 1B 76 B2  53 D1 BA 0E  8B 0A 08 4B  EA 88 46 3C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     5 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     84 56 1F 7D  3C B1 88 02  3E 27 C8 30  18 C6 07 6F\n" +
      "     4B AF E8 F9  7A 35 3C 83  1C 31 52 7C  1C 37 A8 2E\n" +
      "     9D 10 2F DA  45 F7 20 5B  76 27 27 75  B4 D0 6E 3D\n" +
      "     04 2A 23 A6  09 16 4A 44  B2 CE BC 1E  89 48 0D 11\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     6 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     37 93 17 F2  68 D4 B1 88  1F 1A 04 75  86 F9 76 A8\n" +
      "     BF 43 FC 40  0A F8 2B AD  DB D8 FF A2  50 39 C0 B1\n" +
      "     8E F2 7C 36  CF EC 7B FE  80 B9 F4 76  25 54 2D 8C\n" +
      "     89 AF 31 2C  F2 27 95 98  D0 B7 DD B1  BD 06 E7 BE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     7 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     72 08 E0 3C  12 15 EB CC  B4 4A F0 D4  E1 9A D5 D6\n" +
      "     D9 FC 05 62  3D 2B 1E 0F  63 1B 09 12  42 0F 3A 3B\n" +
      "     BE 89 ED 1B  91 18 80 FB  E7 57 21 56  C4 3B 6B 66\n" +
      "     0D E4 FB B8  CE 7C 50 C8  FD 16 D7 EA  70 96 AA 6B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     8 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     40 28 5F 43  36 99 A1 D8  C7 99 B2 76  CC F1 80 10\n" +
      "     C9 DC 9D 41  8B 0E 8A 4E  D9 87 B4 4C  61 C0 1C 5C\n" +
      "     CB CC 09 77  B1 D3 4A 4D  36 65 D2 0E  12 71 6D F9\n" +
      "     34 D2 08 FE  A6 60 7F 74  96 8E D8 6B  E3 C9 98 32\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     9 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     09 9B 62 E2  22 48 0C 7C  04 36 55 81  F7 5E 99 DE\n" +
      "     FF B9 B3 77  D6 72 69 69  C9 13 D4 4F  DA 78 6A EE\n" +
      "     E1 58 78 40  C9 C9 CC E7  3C 70 AD 00  49 AA 25 C9\n" +
      "     FC 1E 83 E6  80 94 76 5B  2F C9 AA B2  AE 14 AE 54\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    10 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     EE 15 8A 4F  D6 5A 35 99  A1 AE 55 27  2C F1 6E ED\n" +
      "     8E 69 54 1A  A8 4E 34 57  7E 22 18 B6  7F 20 F1 19\n" +
      "     6F F5 F9 6E  56 5D BF CF  1C 4D 5A 37  91 AB 1B 27\n" +
      "     87 3B B8 CD  67 B0 DC B1  81 D5 86 33  26 93 4E 47\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    32 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00\n" +
      "Result:\n" +
      "     DD 01 C3 25  31 E8 10 0E  47 0C 47 80  9B D2 1F 84\n" +
      "     30 7B 6B 8D  A6 16 C4 6E  A1 BB 4F 85  B5 47 59 16\n" +
      "     FB 86 C1 3F  AF 65 17 88  AA 17 21 65  18 C7 24 A5\n" +
      "     81 94 8B 42  DE 79 15 96  D1 56 9E BE  91 64 8B 89\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    64 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     A8 C3 7D 4E  D5 47 F6 EC  DC A7 FF 52  AC 34 97 7E\n" +
      "     17 B5 68 D7  E8 F4 9F 0B  D0 6C D9 C9  8E A8 07 99\n" +
      "     9B 11 68 1B  3B 39 0F E5  4D 52 3B D0  EA 07 CA AE\n" +
      "     6D 31 B2 26  D1 A7 07 5F  C3 10 9D 98  59 C8 79 D8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   128 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     FC 71 63 10  CF 81 B8 99  08 44 B1 95  DF A7 65 21\n" +
      "     75 6F B0 C8  F2 60 47 72  05 6B E8 6E  83 DE D3 6F\n" +
      "     25 77 A8 D7  D6 E3 D2 11  2F 46 37 01  6C 75 09 9E\n" +
      "     27 1D F1 2D  DC B3 25 74  33 F9 1B BE  97 0B 84 AA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   192 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     70 8B 36 3C  78 F1 5C B3  9D 85 82 4E  A1 33 98 97\n" +
      "     A0 03 A7 92  C2 A0 19 26  04 B3 89 74  07 58 B3 C7\n" +
      "     D2 34 4C A8  F5 0F 49 3F  30 6D 84 68  69 5B 18 B8\n" +
      "     48 EA C5 23  49 52 E5 AC  47 91 EC 88  E7 18 4C 37\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   255 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     86 4A 3F 1A  1A 29 1C AA  28 07 52 B4  99 11 C0 A5\n" +
      "     D0 7A 04 5F  5B DF E9 E6  66 0C B1 DF  70 8C 81 82\n" +
      "     40 7E 79 B8  A3 81 9B 98  D6 AB 7E 3E  B9 83 9E 7E\n" +
      "     64 70 C5 44  15 F9 2A FD  D4 FA FA 25  52 BB 53 39\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   256 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     49 A7 F0 EE  7C AE B2 8E  35 A7 0C 68  04 55 71 ED\n" +
      "     66 38 8A 6E  98 93 9C 44  C6 32 ED B2  CA 8A 16 17\n" +
      "     CA 95 02 13  45 4D A4 63  E2 DF 5F 32  28 43 63 CF\n" +
      "     38 6A 1E F1  30 87 A9 F8  26 EB B5 C8  6D EA C5 EC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   257 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     A0 55 50 60  F7 C3 A8 A8  C2 A1 14 8F  7A 69 7A 66\n" +
      "     A8 75 10 D5  FB 1C AB 41  CF EC 12 9D  9D ED 18 7E\n" +
      "     B0 FE 29 B2  63 FE A3 D7  D9 76 4B 61  65 1F 92 43\n" +
      "     B0 5B 64 10  F5 F2 D5 C5  CB 89 98 6D  A0 E3 83 05\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   384 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     E5 D3 7D 8D  3D DC 6A 9C  5F 0B 5D F9  B8 40 EB D7\n" +
      "     34 3D 25 EC  20 B8 48 92  BC A4 05 60  39 5D 90 C7\n" +
      "     C7 AB 8E 4B  95 FA 2D 7B  D1 83 F1 8D  8F DF FC 3B\n" +
      "     1E 04 EE 73  F6 E2 D1 7E  92 FC 9C 74  18 3A 1E 8F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   511 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     B9 A8 5A 77  96 F0 AC C5  2F 65 8C EA  F0 8E 7F 6E\n" +
      "     D3 D8 DD 57  BC 26 FB 86  E7 29 5F A5  89 26 C1 5F\n" +
      "     27 F9 6A 7A  7E E5 3E 54  3F 08 EF C6  FD 3B 91 20\n" +
      "     1A 89 E7 06  FC 4E 8C F0  B9 82 32 BA  AE 86 A8 22\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   512 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     33 F7 45 7D  E0 65 69 E7  CF 5F D1 ED  D5 0C CF E1\n" +
      "     D5 F1 66 42  9E 75 DD BE  54 A5 B7 E2  47 03 0D D9\n" +
      "     12 F0 DC 5A  B6 01 2F 59  CE 92 03 AB  D8 2B 31 6D\n" +
      "     F6 7D 5C 6F  00 9A 18 BA  84 DB 03 01  46 DA 99 DB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   513 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     DC B0 0A 11  32 5F E2 88  15 E1 8E A4  5F 99 28 78\n" +
      "     1B CC 06 53  10 6B D1 C1  DE 8E D6 0C  A5 51 F7 F1\n" +
      "     44 75 46 25  2E 56 7D 26  98 A8 40 82  86 5F CE B1\n" +
      "     F2 FE 4D A0  D8 41 D5 6B  3B E1 EA 0E  C0 17 78 C6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   768 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     24 35 9E 4D  A3 9D B5 B4  99 50 87 C3  17 3B D1 6D\n" +
      "     C7 3E 65 AB  7E C1 99 1F  7F A8 A3 DB  23 93 97 DC\n" +
      "     09 C9 46 11  57 D9 39 B2  8F B8 10 7A  13 B3 1A 15\n" +
      "     15 8B D0 0F  85 43 3A D2  AA E4 A1 B0  1B 25 E8 4D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1023 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     C1 05 27 BC  77 C2 E7 DD  FC 8D EB 8E  E6 D8 28 A8\n" +
      "     82 16 F6 89  E5 DC 1A F4  1E F6 39 7E  3B D1 E9 D1\n" +
      "     C8 90 AD CC  FE 68 A6 BA  7C CD B9 C2  96 F1 9B 79\n" +
      "     72 A7 C4 73  FC 29 82 3F  84 A2 48 7D  93 15 69 98\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   160-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     9C C1 81 0D  DF E9 71 CF  71 FE D0 81  5D F8 62 92\n" +
      "     6C 85 CA 6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   224-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     BE C6 A3 7A  9F 08 6B B2  39 7A E1 BD  F0 00 EC 5E\n" +
      "     B8 7A D5 80  39 F3 61 23  A2 7E 0E F1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   256-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     2D 0E 2E 24  19 72 DF 39  BE 82 2A 8C  68 21 05 C6\n" +
      "     47 47 FA F8  A1 0E C0 32  88 1D E7 DC  67 88 7C C2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   384-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     E6 3E A4 69  8F 31 4A D9  F8 F8 CB D1  F3 36 E0 27\n" +
      "     95 5F 8D CE  78 C3 21 0A  F9 B1 F4 6B  D3 28 36 7D\n" +
      "     8E 88 D4 31  07 1C 43 85  CD 8B 50 D7  48 62 C2 48\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     FB E6 5B 75  D6 81 B2 FE  35 47 80 BD  DF 82 CC F1\n" +
      "     64 C5 CB 28  27 F8 E4 E7  DE 96 23 59  07 44 34 28\n" +
      "     95 78 81 C7  6C E4 65 55  E2 BB 9E E3  4F 42 F7 A9\n" +
      "     B2 E0 90 B5  5D 73 C7 A0  25 06 E1 7B  BD FF A4 F2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1024-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     4F C4 31 53  37 41 6A 60  15 74 C3 77  20 5A C5 17\n" +
      "     23 5D AE 3D  39 C8 48 5E  A5 19 08 AC  86 FB 43 55\n" +
      "     D8 5C E6 BC  6F 2B 65 38  D9 BD B0 8B  69 4F 8F DA\n" +
      "     4E 46 64 2A  EE 61 43 84  28 E6 EE 7E  C1 F9 4E AD\n" +
      "     C0 09 96 F3  A4 41 AA A9  1C 96 C1 91  67 F1 AB 21\n" +
      "     0B 6C 99 AB  3D 64 95 92  16 6F 74 20  A9 94 C9 BD\n" +
      "     32 BC CD E2  63 91 B0 9C  EB 81 5E 2A  12 E3 DF 80\n" +
      "     60 5D 70 78  FB 1B 8F CA  F0 1B 17 54  CC 27 1B 6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   264-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     24 39 4D D2  1F BA 42 A1  D5 D2 30 2A  23 7F CF EA\n" +
      "     34 5E 6E 45  C3 C7 D0 EA  9A B9 AE 37  4C 96 22 C3\n" +
      "     10\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   520-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     C7 78 61 B1  FC E6 7C 93  63 09 68 F2  1F 9E 3D 0C\n" +
      "     24 D3 47 0E  CE E2 05 EC  56 19 2F 23  00 E4 3B 56\n" +
      "     D3 C0 63 F6  59 68 75 09  2A 10 8E 8A  D3 4C 42 0B\n" +
      "     C2 F6 97 8D  4F 3C 2B B6  E5 39 49 A5  06 51 E0 0E\n" +
      "     2D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1032-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     A9 75 80 15  F0 89 2C 5C  FE 64 86 04  BA 7C C4 87\n" +
      "     FB 6A CB 74  B8 AE C2 8D  CF 24 A4 41  1C CD 46 39\n" +
      "     B6 02 2C CA  7A 11 F8 B3  EC D3 E4 FB  E5 23 B0 F7\n" +
      "     AC F0 3C 57  FD 22 CD A2  8E EE 38 95  67 14 95 02\n" +
      "     B2 55 83 14  79 2B 6C 01  EB 72 50 E0  4F 79 4D D6\n" +
      "     CA 62 FF EC  EA 43 B2 29  E3 1A B3 9D  3B 16 01 95\n" +
      "     85 47 FB 13  3B 38 7C E9  86 A1 12 B6  53 5F C5 82\n" +
      "     67 DB 07 BC  0B E6 19 BA  D0 7F C6 D3  F5 53 79 B2\n" +
      "     17\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  2056-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     9C A3 3B E9  20 C5 2D 37  A4 12 17 4D  42 73 C7 1C\n" +
      "     10 AD 2F F2  CE C2 F2 39  9E 14 BD 05  D5 85 42 AF\n" +
      "     82 E4 E4 47  2A 9C 21 A9  D5 D3 56 25  A9 03 C6 92\n" +
      "     5D F1 88 C8  23 26 B7 41  DE 2B 66 02  FA 09 0C 74\n" +
      "     3F DF C0 F1  0E 08 68 ED  78 BB 06 7C  F2 8A F3 C4\n" +
      "     E0 43 B6 69  F6 7D 99 AB  DC C3 C4 99  CC B9 C3 71\n" +
      "     8F 49 04 1C  93 D8 77 96  60 7C C7 AD  52 DF 4F 92\n" +
      "     86 42 2E 4E  D2 3D C2 DA  1A 45 23 A1  58 CB 7D 3B\n" +
      "     C7 79 2C 80  8D 09 43 E1  2C 10 3A 6A  FE 68 8E 58\n" +
      "     6E 9F 39 C0  EA 88 E1 66  6F 84 06 3C  67 00 F5 4B\n" +
      "     FE 39 59 B5  FC 91 16 D9  21 A0 33 1F  3A 78 5B 37\n" +
      "     3E DA 08 F5  FD A3 39 B6  D7 E8 3D FE  9B 40 3E 39\n" +
      "     A2 20 4D D5  65 8B 50 23  CA 89 95 80  D7 49 F1 77\n" +
      "     0A 1D 5F 64  A3 B7 0D 04  8B 15 D9 0F  FA 7B 2C 22\n" +
      "     A1 B2 B5 7B  84 20 AB 9D  05 3C 90 7A  8B F4 33 E4\n" +
      "     28 F9 8F 31  EB 18 E8 9F  D5 45 0F 68  6D 8D E8 19\n" +
      "     20\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1025 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     E4 BB 39 F4  1F FD 4C 58  35 60 DC A8  1D 0E B7 82\n" +
      "     0A BA 4F 43  AF 3A 58 68  09 CB FC A2  3D 62 92 47\n" +
      "     3A F2 A7 98  28 97 85 88  48 84 FB 62  44 53 DE B1\n" +
      "     6D 59 DC DA  F9 B2 31 5F  6E 06 BB E4  1E 38 EE 54\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2047 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     C5 5A 80 88  FF 7E 91 49  BD 5B 93 09  42 3B 5E 2C\n" +
      "     FD 1D 58 68  04 76 48 92  BC F7 79 4E  57 B3 FF 4E\n" +
      "     FD 6E 3D BE  CF 9C F4 B1  C9 1B 91 F7  A6 DD CA 37\n" +
      "     FB 69 72 41  63 42 5B F3  CF D1 1A 1E  B6 09 80 FF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2048 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     D7 4F 3B 94  6A 59 D1 6A  50 FE D3 47  86 AC B2 3A\n" +
      "     EB 60 69 A1  56 7B DC C2  44 2A 54 C7  4A 4D 41 A2\n" +
      "     4A 62 F3 F1  A7 6C 6B B4  4B D5 4A ED  F9 4B 40 F5\n" +
      "     3D 93 35 15  45 30 98 6C  D4 F5 AA 16  F9 3D 2D 24\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2049 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     B6 1F 47 B2  E9 07 A0 28  08 B0 77 64  DC 04 78 16\n" +
      "     22 85 7A 66  9B EB F6 EC  A2 E6 7A EE  9A AD A5 25\n" +
      "     51 EF A5 7F  21 FE D7 52  78 AF 2C 9D  D7 54 AB 1D\n" +
      "     B7 9E A6 A5  C1 F5 B0 93  12 04 9C 7D  73 5A 9D F0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     0 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     0F FF 95 63  BB 32 79 28  92 27 AC 77  D3 19 B6 FF\n" +
      "     F8 D7 E9 F0  9D A1 24 7B  72 A0 A2 65  CD 6D 2A 62\n" +
      "     64 5A D5 47  ED 81 93 DB  48 CF F8 47  C0 64 94 A0\n" +
      "     3F 55 66 6D  3B 47 EB 4C  20 45 6C 93  73 C8 62 97\n" +
      "     D6 30 D5 57  8E BD 34 CB  40 99 15 78  F9 F5 2B 18\n" +
      "     00 3E FA 35  D3 DA 65 53  FF 35 DB 91  B8 1A B8 90\n" +
      "     BE C1 B1 89  B7 F5 2C B2  A7 83 EB B7  D8 23 D7 25\n" +
      "     B0 B4 A7 1F  68 24 E8 8F  68 F9 82 EE  FC 6D 19 C6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     1 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     D1 9B 5B 64  40 EC BD 3E  C0 25 BF AB  19 25 F2 1D\n" +
      "     2F 15 5C 28  77 83 04 6F  7E B8 C6 8B  34 DF 08 7B\n" +
      "     64 87 BA 6D  E4 15 C0 96  C8 D9 B4 EF  B3 D7 B1 AC\n" +
      "     2A 1D ED CA  7C 46 7E 6C  AC 0E D3 F2  A9 0B 40 B9\n" +
      "     EE C9 3D 5B  20 8B 55 69  D4 88 FC 86  D4 38 40 2C\n" +
      "     E6 1F F9 4A  00 80 2C F4  BA E1 F4 C2  73 A9 BA EB\n" +
      "     D9 D9 B0 D6  0E 3A F4 81  E2 5B EF D6  9E E7 1F 36\n" +
      "     D9 EF 20 4A  19 42 CC FA  E4 E3 3F CB  0B A5 D9 80\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     2 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     8E 54 9F C3  BB D1 E0 14  B1 66 CF 75  15 A1 4E 30\n" +
      "     C1 80 51 9A  24 F9 42 C8  53 07 15 D5  9D FB 14 B9\n" +
      "     4D 14 B7 DE  42 8C 64 28  28 B0 0D 11  3F 6A A4 30\n" +
      "     52 20 A4 19  E6 22 EF 4B  F2 FB 7B 86  37 A1 7A 5C\n" +
      "     E5 CB A9 43  4F 34 6B BF  45 52 56 9B  2A 22 27 66\n" +
      "     03 73 F5 EE  1C F7 24 21  0B 37 83 E8  75 C2 6E 47\n" +
      "     ED CB 0E CD  A5 C3 67 9D  BD 6E EC 89  DB 69 7F A9\n" +
      "     DC 2B F4 C0  4D 20 FD 59  C3 7C B6 C7  01 5B 0F 9E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     3 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     FC 4D E7 38  69 A3 10 B2  26 91 25 CE  53 72 41 E1\n" +
      "     05 84 C9 BC  B1 59 8F 51  CA FA 2D B5  E7 BA E1 B1\n" +
      "     33 02 47 87  59 52 6B D1  BD 2D 82 13  00 A2 D4 48\n" +
      "     7F 44 7F 01  69 F2 0B 1B  8F 19 A1 97  3A AB 57 53\n" +
      "     F7 54 AF 08  04 17 F9 4A  68 54 1B F8  DB 8E E8 46\n" +
      "     44 AA A6 CD  02 55 94 64  43 CD 10 21  37 F9 54 5C\n" +
      "     AD E3 60 14  12 80 B3 8D  41 38 37 B7  42 35 85 A6\n" +
      "     E5 14 DA D1  4E 5F E8 19  3E 9A 64 8C  7E FD 3B 4F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     4 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     E9 58 73 18  B7 AB A0 94  2A 13 17 9B  9E FD 67 42\n" +
      "     2A 66 86 47  8D D7 02 51  1F 9F 35 CF  0D E2 B0 7D\n" +
      "     51 22 B7 BD  5A 87 C3 93  01 6B 35 95  EB 06 C3 AE\n" +
      "     ED 10 CA 8E  09 99 04 E9  80 8D 66 52  FA D1 E4 4D\n" +
      "     34 5E 49 59  C1 B9 7F 44  3C 92 BA 38  97 75 34 9B\n" +
      "     52 DE AC FE  E3 13 00 80  56 DC F0 3D  3B 13 9E 16\n" +
      "     7A 9A 20 8E  0D B7 36 51  27 42 F6 F3  44 FC 89 5C\n" +
      "     69 26 A2 D9  9A 21 CF 0F  99 BA 84 BE  E5 86 D1 2B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     5 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     5E 8C FF 2D  02 D2 E5 AD  48 30 83 EE  85 08 F0 44\n" +
      "     88 36 DF F8  EF 4D 52 B4  A8 59 49 C3  63 8F 8A E9\n" +
      "     AF 7A 5D 43  C9 9B F1 92  54 69 B2 CA  01 19 6B EB\n" +
      "     54 02 5B 88  1E 7C CE 9B  F0 88 E6 6F  17 4E E4 81\n" +
      "     33 B4 00 C3  8E B2 6D 4B  54 48 35 1F  59 15 38 C9\n" +
      "     88 8F 59 8F  8C 10 22 0E  04 51 89 6D  74 3D 61 82\n" +
      "     60 78 9B 2C  07 CC 77 D2  00 00 EC FA  46 4A 5F DB\n" +
      "     A6 E2 B3 94  44 A8 EB 75  F0 01 9E 8C  AC E7 9A BA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     6 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     25 24 AA A6  79 11 C3 9E  74 10 C6 85  1A 53 BD 82\n" +
      "     63 FF CA 4D  9E 27 30 35  4F E0 86 D1  24 0F A8 1F\n" +
      "     0C 99 DA 44  14 90 16 78  54 4E CA 75  4B 70 97 17\n" +
      "     0F 32 45 85  14 40 41 68  95 28 33 3D  EF 59 C7 00\n" +
      "     3C 34 AF 4D  65 52 39 36  58 35 49 C3  F8 94 B7 49\n" +
      "     4E AA 62 51  C3 5B 48 0C  DD 73 D0 4E  B7 56 DC 6A\n" +
      "     52 06 78 1E  D4 D9 8F 37  66 15 76 74  FD 32 C2 3C\n" +
      "     1A 84 95 79  E2 60 F7 B4  57 7B D9 5E  D2 82 AA 2D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     7 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     D9 87 B0 05  F2 5A 88 CD  FA B8 09 C1  CC 99 8B 6F\n" +
      "     67 C8 F8 CE  7A 11 3C 14  BD A3 26 29  D3 F5 CC 30\n" +
      "     0E E2 94 DB  50 F4 3A 90  BC F5 73 04  E7 BE 1F 35\n" +
      "     D2 C4 55 99  0A DE 29 F6  A5 8E 05 67  C0 F8 06 CC\n" +
      "     E0 A4 0B 88  66 34 5D DC  F6 A8 CF 29  CB 44 FA 03\n" +
      "     27 9C 58 76  47 9B 45 D7  BE 3E 72 B6  BE 9D AA 1B\n" +
      "     0B 3B 48 F8  48 51 83 0C  30 B5 1E 42  69 8D FA EA\n" +
      "     30 42 E9 A5  90 AC D9 5C  2F 28 82 29  B4 70 05 04\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     8 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00\n" +
      "Result:\n" +
      "     CC 66 6D D8  2A 8D 4D A4  88 00 26 5F  75 ED 5C 08\n" +
      "     94 E5 97 12  2F 6B 55 47  A9 39 2F 2D  25 AD 55 62\n" +
      "     C1 F9 05 61  E7 02 84 E1  9E C0 D1 FD  20 B3 7F D0\n" +
      "     97 82 3E 28  90 91 5B D0  9A 4C E4 73  AB 9F A3 80\n" +
      "     F3 2C F8 64  F9 72 CA 12  03 D5 23 75  AE B0 71 F7\n" +
      "     15 9F C9 EA  D7 54 8B 52  B0 1F 4A 0B  37 70 46 BD\n" +
      "     6F E9 DC D6  92 31 2A 5B  60 30 BD DE  C5 A4 ED B9\n" +
      "     3C 56 81 67  49 0A C5 46  B4 A6 AE A3  F6 30 31 91\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     9 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     8E FE 18 60  A8 6D E7 55  BA 08 A7 CD  65 59 51 CD\n" +
      "     6E 6B 84 26  BD EB 3D 98  63 9F DA D6  EA 41 3B 55\n" +
      "     D2 DB D0 54  92 01 99 55  DD 43 61 45  CA 1F 82 C5\n" +
      "     CC 3E B6 2D  18 DE 23 16  D7 70 03 AA  70 CD C2 2D\n" +
      "     C0 AC AE C3  0A 03 2C 68  52 8B A6 0B  40 89 02 90\n" +
      "     72 7C 27 EA  BE 07 B5 E8  A9 28 B3 B1  7C 40 D0 DE\n" +
      "     63 70 29 50  EF 44 DF 1B  20 07 D7 29  39 51 AC 8B\n" +
      "     01 41 2C 54  5D FB 52 4C  B3 67 1B BA  CB FB 26 E1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    10 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00\n" +
      "Result:\n" +
      "     3C 19 E2 1C  C9 48 50 C5  BD C3 3A EA  76 AE C0 92\n" +
      "     C9 30 B0 6F  04 4B C4 DC  53 AC 26 7B  84 DE EC F5\n" +
      "     91 C7 23 5C  AE E1 64 E0  B0 4D C8 93  C7 86 D8 31\n" +
      "     9A FF 40 50  2A 17 F9 FF  75 0F 64 67  5D 41 08 AF\n" +
      "     3B AE 97 2F  0B 4C 29 B4  C5 FC 2F C4  E5 13 24 84\n" +
      "     FB 9F 25 9B  CE B1 89 8A  FF 78 5C A0  3B F6 5D 11\n" +
      "     44 96 90 DC  86 1C A1 45  9F 30 17 E1  77 3B BB 46\n" +
      "     84 16 39 A6  72 C6 5A 18  8D 0A D1 28  B6 A8 23 D1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    32 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00\n" +
      "Result:\n" +
      "     B4 C6 A5 C2  31 08 57 3B  3A 4F 0E 06  92 B9 BE 53\n" +
      "     E6 E0 16 44  C5 15 21 48  FE 93 B3 B2  81 E3 45 0D\n" +
      "     5D D0 FE 3F  62 16 09 6D  48 97 B0 E8  65 F6 AF CE\n" +
      "     1C 13 17 09  15 30 99 CB  1E 86 28 6B  15 C4 2E 83\n" +
      "     65 C4 51 B8  E9 7F 04 6D  2A 7A 41 28  AD A3 BC 68\n" +
      "     AE B8 D5 9D  60 4B 12 75  C8 9F D3 F6  35 11 88 BF\n" +
      "     82 ED E1 BF  4F B4 B2 2F  A4 58 AE 8E  D3 41 94 66\n" +
      "     B6 EE 21 53  92 01 12 AB  BD 6A 66 0F  E8 C9 49 E0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    64 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     BB 80 34 F4  41 A8 2D 5A  14 3D 19 FF  E5 52 B7 96\n" +
      "     25 13 4E 9D  BE 14 DC 51  4F EC FE 7C  33 12 F3 0C\n" +
      "     63 3B 36 1C  68 6E FC 46  07 FE 81 63  99 EE AE F3\n" +
      "     9D 4E 9E 81  F0 FE AB F6  73 F0 D7 79  88 46 FB DC\n" +
      "     4D D7 7E 75  FF 8D 97 70  43 03 1B F8  08 39 06 3E\n" +
      "     4A 03 03 E1  19 38 FB 2F  5B 28 9C 58  98 17 74 A5\n" +
      "     7A 51 6E 0F  47 E9 0A 08  D8 2F D3 A2  D0 DC 28 7C\n" +
      "     6D C7 22 B6  FF A7 E5 95  0C 65 89 2B  55 1E 18 7F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   128 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     B6 90 A3 09  B7 AC 0E F4  68 F9 C4 7D  4A 50 F7 AA\n" +
      "     3A 78 24 26  DA 68 F9 6A  2A E7 FB A5  E8 89 20 6A\n" +
      "     5D E0 D6 1A  4C 68 40 EB  14 FD 1F 50  58 11 B6 C1\n" +
      "     4E B2 F0 0A  81 C6 1E 31  C7 9C 02 3D  75 92 4C 6E\n" +
      "     52 ED 48 2B  9B 9B 5B 4B  2B DD 5F C4  4F 7A 42 9F\n" +
      "     51 D0 95 41  3C 9E 78 0E  C6 92 A8 DB  58 1D D1 58\n" +
      "     5B 6A 67 BE  35 B4 0E 7D  4D 49 6A 94  E4 73 87 F6\n" +
      "     1E DB 27 FC  6E 8E 32 86  0C 5B 8B 04  6E 0A 75 11\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   192 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     56 7D 7D E9  43 79 FA 5F  83 26 6F FF  C2 09 45 FD\n" +
      "     84 B3 D7 96  5D 56 B6 A2  AC 84 3B 2C  7A 24 E4 92\n" +
      "     E2 C4 98 41  1B BC 1E 38  E6 A3 D1 5B  D1 3A 19 2D\n" +
      "     7B AC F2 88  5E AB D6 C1  9B A1 3F AF  26 B7 30 0D\n" +
      "     1C 2B D5 28  2F A0 59 A4  C2 C4 B6 9B  D6 03 20 BF\n" +
      "     0E 1C 48 28  5F 84 F4 A2  A6 38 06 AB  4B C4 61 7C\n" +
      "     60 F7 31 AC  9B 3F DF 91  04 3F 75 C2  93 C8 B5 43\n" +
      "     AB 49 C4 2D  18 5F EF 4F  25 F2 47 9F  CD E2 29 5F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   255 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     41 D6 01 57  02 26 C9 13  F9 8E C0 91  49 7C E4 9A\n" +
      "     04 BC 34 EF  5F 77 F4 02  37 1C 33 BD  44 85 26 F8\n" +
      "     32 0A D3 CF  9B 48 CB C1  5C B0 E2 7A  48 A4 5C A5\n" +
      "     0E CF 1D E3  C6 DC E2 FB  4B 49 96 D8  DF 0E A0 8E\n" +
      "     00 A3 36 74  FD CA 10 6D  B3 5F 0D C6  08 EB 95 58\n" +
      "     C1 43 FA 4A  92 8A 76 57  AD 92 46 53  77 87 38 24\n" +
      "     09 E3 BB 67  F4 56 54 44  8D EE C4 64  C1 CC 9D 27\n" +
      "     CA 70 B0 E0  F6 54 48 7C  5A B7 DA C8  E0 EC 3B 72\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   256 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     32 73 08 74  67 48 85 78  33 0F F2 DE  C2 9F 69 10\n" +
      "     89 BC 95 C7  70 F5 AC 37  57 1A F4 0C  09 2A E6 E1\n" +
      "     24 D1 F3 AC  80 17 EA 44  3D 67 20 96  78 C2 69 4A\n" +
      "     62 8F 22 3B  BE 4B 76 A2  BE B6 3C 61  17 28 7F 78\n" +
      "     2E 7D DF E3  FA C3 A9 A3  58 25 91 CC  1F 9C 57 A6\n" +
      "     C1 81 D1 36  9A B3 AD 23  40 60 6B AE  F1 1C 3C CD\n" +
      "     6E 09 0B 69  54 A5 E1 10  23 92 B2 78  1E 98 69 C5\n" +
      "     1E D9 33 8A  3D 32 C9 F7  06 C0 28 E2  DA A8 7B CA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   257 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     97 72 24 B4  11 C0 51 81  B0 A5 63 D4  6E 3A E3 02\n" +
      "     D0 CE 5B 72  C7 E6 A0 8A  6D 03 6B 6A  76 02 71 9C\n" +
      "     45 15 2A D9  01 80 AB 28  EB A8 46 8B  9C FA E6 1E\n" +
      "     5D 09 C1 11  CC E5 DE 57  74 27 D4 D0  5A 08 5D 5E\n" +
      "     69 37 3A 3C  35 60 5D D0  70 0C 76 99  E7 67 AC BD\n" +
      "     12 2E 09 BF  F7 A3 6E DC  60 44 D8 33  6E BB 26 B3\n" +
      "     AA 65 86 AD  CB E9 9A 53  2E 7B 79 82  A5 A8 CE 32\n" +
      "     BB 0D 7C 61  D0 F9 BD F0  74 9E 5D 1E  87 8A 19 26\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   384 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     18 02 D7 05  C2 41 81 EA  A3 1B A8 B4  6A E8 18 06\n" +
      "     C1 F3 E9 2D  AE 65 AA B9  25 4A 1F 99  C2 F3 10 89\n" +
      "     1C FC EF 5F  22 1A 6E AA  99 58 90 B9  A9 57 20 C6\n" +
      "     F6 D9 73 07  BA 4F 62 D3  DC 7B 85 FB  F9 8F BB 70\n" +
      "     2D 64 E5 11  FA CD 98 EB  D5 99 4A 6F  C8 81 FA 5A\n" +
      "     64 0F C1 BD  FB EE BC 95  4E F1 73 E8  99 45 4B 3B\n" +
      "     1C A5 AA 87  1A 12 09 AF  83 6F 2D 5D  AA 54 BB 98\n" +
      "     26 8C 1B D6  E8 4B 0E 99  7E C9 93 48  A6 AB A7 E2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   511 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     A1 8A EA 5D  11 D9 AE 89  75 4B 1B 97  13 E8 51 D5\n" +
      "     E2 D0 10 35  D2 05 F1 EB  82 E2 A2 5F  9C 7F 4E 0F\n" +
      "     C3 A8 DD 29  F8 BB FC 86  F7 86 B5 5A  61 DA 7E 7F\n" +
      "     DC 0D 79 F5  08 61 D7 33  B9 90 A9 1E  D1 7E CF E8\n" +
      "     A6 FA C5 C0  B7 AF C8 9D  A0 D0 1B A9  C7 2C 21 00\n" +
      "     B1 FB 1D D5  E8 2F 15 58  38 11 97 A3  D3 68 A4 25\n" +
      "     ED E7 ED D9  E8 E5 40 8F  24 4D 7F B7  7D 5B 6D A3\n" +
      "     96 51 BE D2  F7 6C 9F 2B  4F 5D 82 95  69 69 FE 8C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   512 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     B0 01 53 6B  A6 C8 FB 70  00 49 B2 E8  F6 2F 93 31\n" +
      "     94 F1 3A C3  E9 6E 99 42  F8 54 C9 59  51 0D 41 7A\n" +
      "     E0 D4 36 B0  2A 7E CC B1  EC 3F 17 C7  E8 BC 27 8A\n" +
      "     23 A6 69 0E  BF AC AD A0  8F 26 6E 28  D6 02 51 3A\n" +
      "     8F 06 72 9A  91 B9 D0 E0  67 E6 CE 4B  3F 95 42 F0\n" +
      "     04 B7 3A 6A  E3 21 0E EB  1A 41 F7 6B  D0 D7 FA E2\n" +
      "     FB 03 55 E7  37 58 B3 D1  FC E0 2E 8C  13 00 CB 69\n" +
      "     DB 99 FA F9  5A 7B D9 1C  42 FA 6F 65  25 A5 2B 34\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   513 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     8A D3 60 FA  B8 49 3B 8D  9C 78 C4 15  6D 1C 8E 3E\n" +
      "     93 31 6E AF  22 34 A9 0A  A4 0C AF 5E  C9 A6 68 67\n" +
      "     58 D1 72 C3  A5 7B 36 20  AC AB 28 F1  61 B5 10 5E\n" +
      "     AA 0A B7 F3  EB 71 07 D5  E6 97 B3 51  5A E3 C4 18\n" +
      "     E2 0A F6 22  FE 8C 01 C0  75 17 8E D7  C1 9E 24 BC\n" +
      "     D6 58 D8 31  D3 EF CD EB  6C 12 55 1E  9F F6 E1 04\n" +
      "     D1 C6 48 4B  00 E3 AA 1F  94 B1 B3 44  46 6D 41 CB\n" +
      "     98 7E 0C FD  77 47 05 B9  74 41 EC 6F  13 13 DF 9D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   768 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     F8 55 17 38  13 D1 24 CE  99 66 14 2D  F6 4D C4 F2\n" +
      "     F8 82 B5 9F  AC 63 AD 51  2E 2A 6F 69  F0 BE F5 C2\n" +
      "     5C 28 BE CC  DA A9 D7 20  67 F8 88 66  47 4D EB B5\n" +
      "     9A 42 26 D2  BD 6D 03 52  C7 55 B6 E0  9A 77 EE 98\n" +
      "     1B 5D 1D 29  D9 36 52 7C  1B 94 3A 25  88 42 0A B8\n" +
      "     1C 93 B4 59  BC F4 AD E1  D2 6F 6E BD  C1 92 71 0E\n" +
      "     70 90 D2 3C  1A 18 9C 7C  EE A3 0A 6F  D6 D3 A3 A6\n" +
      "     A6 C9 63 BB  EE 9A A6 48  99 7B 2C 59  90 69 FC 74\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1023 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     B3 C6 2C 7B  92 3E 67 BE  49 6F 8E 6D  D4 7E A4 E0\n" +
      "     04 32 9F 96  63 E6 35 4B  14 D7 3A E8  E9 CD 29 01\n" +
      "     4D 06 2D 64  44 EF 0E 89  52 56 3C 21  4A 46 89 96\n" +
      "     C8 8D 20 18  C3 B9 FA B4  84 84 48 57  1B 55 85 3D\n" +
      "     D5 12 5A 59  9B 44 2A CF  00 75 5D 91  13 26 FD 62\n" +
      "     CB 49 D6 4E  13 D2 20 D1  44 CF 29 C4  24 6E CD 52\n" +
      "     E7 C4 2A 4F  99 1D DA DD  DD 5A DF B1  03 32 9E F5\n" +
      "     02 2B 69 87  3F 5A E9 CB  4B 2C 1E F9  E8 8F F4 F8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  160-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     7C 94 3C 8C  D2 BE 40 4E  87 C3 A0 FD  B5 04 99 A3\n" +
      "     95 44 7A 84\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  224-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     A7 BF 35 94  3E F2 09 C7  01 C0 66 DA  52 26 69 70\n" +
      "     D2 44 A5 8F  08 C2 7D E5  4B E7 41 34\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  256-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     35 EB 69 E5  04 AF 45 4E  83 4A F1 A4  73 41 8D 69\n" +
      "     B7 26 38 DD  75 68 95 75  39 AB 6A 15  48 39 F4 E9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  384-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     B4 0D 9E 51  10 DF 88 37  6A A7 44 D6  55 44 D2 6E\n" +
      "     8C 57 05 B2  D4 61 EF F6  FA ED 65 EB  CE 94 58 3F\n" +
      "     FC 53 99 A5  FA C0 0B FF  11 84 52 3B  C5 5B AC 0A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  512-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     2D F8 9E 10  21 07 1C 13  6C A6 8C 02  0D 0A 67 0D\n" +
      "     98 0D C7 75  0D 23 BB 08  4D 7B FF 10  CA 2F 2F 51\n" +
      "     FA 1E 58 4D  A8 58 DF 1F  C5 82 87 B7  C6 F2 BE C2\n" +
      "     C4 8D CA AF  CC D3 5F 46  82 E6 87 59  B6 2B 6A 70\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     81 18 D1 74  A0 BC 09 50  5A 2F 67 7C  6D CB C1 B8\n" +
      "     C5 A7 C6 72  0F 6C 59 D6  0A FB C7 CD  6F 64 E2 0A\n" +
      "     92 B6 40 95  C3 9E DB 56  A2 F4 7C 26  83 C5 11 6F\n" +
      "     F3 58 FD 96  9E 76 D4 4C  1F 50 C9 2B  26 17 1A 33\n" +
      "     FA 9E EB AF  0D 1F 32 0D  41 44 BC 97  EA 00 D5 9F\n" +
      "     00 59 86 43  43 9C C1 3B  BD AD DD E6  67 1A 89 E9\n" +
      "     A4 0D 30 02  A2 93 00 E7  C6 65 B6 06  D8 B7 16 72\n" +
      "     54 78 7C 86  7B E8 14 1A  56 E8 D1 14  58 65 CC B9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  264-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     EB 10 A2 4C  CD 60 A8 A1  12 1B 72 AC  09 4A E3 58\n" +
      "     34 94 00 7F  57 64 34 52  C6 3E AE 9B  FF CB 4E 40\n" +
      "     41\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  520-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     28 30 B7 87  DB 1A AF 66  52 92 C4 F6  5B EB 75 38\n" +
      "     12 33 15 51  C2 41 DC EC  91 E6 97 9E  9F FC 04 5C\n" +
      "     CF DB 2D 86  70 DE 81 DA  38 F8 E2 04  BF C2 00 EF\n" +
      "     C6 F9 2F F9  F6 AA 13 17  E2 C6 17 B9  A4 28 5B B2\n" +
      "     2B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1032-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     26 98 D7 23  40 6F 91 42  89 D0 04 A6  17 69 65 FC\n" +
      "     25 34 E0 50  92 EA 5E A8  8D 7E E9 21  8C C1 07 7F\n" +
      "     A1 1A 12 9B  76 AB 3A 24  D0 69 49 C5  99 D9 47 29\n" +
      "     E8 A3 D2 9D  C7 C0 5B 4A  A5 36 2C CD  F3 F2 32 3A\n" +
      "     5B 63 F3 4E  C5 D7 1D A7  9E AF 2C E5  F5 F9 89 A1\n" +
      "     7F 80 A9 37  07 5E 71 7E  E8 B6 37 DB  49 C2 60 8B\n" +
      "     B8 4F 27 6C  34 D9 37 5B  C2 D4 A4 29  F6 63 0A 24\n" +
      "     5C F2 01 7E  7C 28 45 E3  37 F0 A4 F7  63 C5 63 AC\n" +
      "     4D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 2056-bit hash, msgLen =  1024 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     5B 2D D6 A0  44 5A FB A8  2B 84 E8 70  90 72 F7 72\n" +
      "     61 4A B2 CB  7F 28 23 19  59 62 20 6F  16 3F 25 0C\n" +
      "     66 36 30 E3  27 73 EC 73  42 7E B7 99  FE AC 47 50\n" +
      "     FB 85 49 33  2C 45 BF 1F  EF 12 69 3D  F7 44 CF BA\n" +
      "     61 A2 04 1C  3E EC DC 8F  8E C8 DB CD  3E 76 C4 C8\n" +
      "     D8 1B 20 8E  87 E3 C9 6F  7A AE 95 7C  61 41 CE D5\n" +
      "     56 37 42 97  05 B4 63 B8  8E 10 0C BD  5F 25 12 37\n" +
      "     F5 5A E2 E3  3C BC 8F CC  1C 96 04 67  58 F9 94 FF\n" +
      "     FD 7B 8B 68  A1 FD C7 27  00 43 9A E3  80 66 5F DD\n" +
      "     ED 73 74 F1  8F 5F 8F B5  84 32 91 C0  5B 1D BC 0C\n" +
      "     B4 20 26 33  74 03 F9 AF  D4 84 53 62  5B 47 93 66\n" +
      "     DF 41 C8 A6  20 C6 AA A7  B4 AC 06 18  13 02 F3 13\n" +
      "     4F CF 60 25  09 67 B8 C7  B1 D0 C3 2B  B9 5E 40 D2\n" +
      "     4E C3 77 69  45 3B F2 1F  C3 60 DC BB  9B CE 3F E6\n" +
      "     82 49 C5 FE  44 CE 9B F8  06 86 C2 96  1E 1D 25 86\n" +
      "     CE 63 E8 1A  33 BB 00 31  F9 C3 F6 D3  45 D5 95 DE\n" +
      "     CF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1025 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     85 D6 51 D7  E8 1C 1A CD  15 1F 4E E6  D0 F9 8E 1E\n" +
      "     88 45 F3 19  03 29 6C 43  04 34 46 12  93 D0 43 2E\n" +
      "     64 E4 22 9C  E7 F3 88 5D  E5 40 7A 6A  0A 68 6E 67\n" +
      "     1F 86 58 08  77 D8 40 65  7C 16 2D 79  8E A9 34 96\n" +
      "     7E AC 30 78  B5 A2 DF 3C  D4 4C 47 45  E4 CD A7 9D\n" +
      "     81 70 16 BC  A1 4A FD E6  12 04 6D 16  D2 36 C8 D4\n" +
      "     08 EF 3B 91  B1 CC 03 4A  46 B1 44 42  7D B0 EC 2A\n" +
      "     1D 75 8A 41  DC 47 35 D9  BD 15 75 70  09 14 03 06\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2047 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     6F FE 3F B8  4E CB D1 09  17 D8 71 3C  65 EE 99 E4\n" +
      "     AE 5D BA 1D  C2 88 B0 A7  0A 27 B1 86  C0 8B 0A 83\n" +
      "     CD CE AE 23  5C C9 04 95  BA BB D6 E7  DB 1F D2 62\n" +
      "     D5 CB 32 E7  27 8A 9F 36  3D FE 32 4E  E3 E2 C3 51\n" +
      "     18 E9 14 DF  17 BE 06 1A  D9 97 72 34  E5 F5 10 8F\n" +
      "     1C 47 BE BB  87 8C F1 26  CA 69 8A 60  DC EA A3 91\n" +
      "     64 12 C3 FD  3C FF 63 EA  6E 4C 68 10  B1 E1 C9 C5\n" +
      "     73 CA 40 9F  78 E0 1F F3  41 0C 24 46  45 EA 2B 1B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2048 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "Result:\n" +
      "     4A C1 25 1B  3D 81 64 88  C7 81 71 D9  33 18 F1 44\n" +
      "     C6 96 26 15  29 7F DD 33  7A C2 28 80  79 1C 41 90\n" +
      "     99 F5 F7 A5  FC 8F F3 80  5C 39 81 02  73 27 CD 8C\n" +
      "     63 3F 39 A6  FE 2B 5A EE  E5 15 39 76  A3 6C 90 99\n" +
      "     F6 00 AE 87  4E 9C 07 E5  7E 15 60 B8  D8 ED 91 35\n" +
      "     26 3E 27 C2  02 7B 5F 71  20 A6 2D C3  26 67 E1 0B\n" +
      "     10 E6 FD 23  0B 5B A1 A4  E0 4E 92 F5  18 2B BB 57\n" +
      "     00 80 0B C2  68 4A 43 9A  78 E0 F9 25  EC E3 DE 86\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2049 bits, data = 'zero'\n" +
      "\n" +
      "Message data:\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00\n" +
      "     00\n" +
      "Result:\n" +
      "     E0 61 E9 8E  BA AF E4 C1  F1 DA A6 BA  AA 75 69 F3\n" +
      "     A9 BC 17 73  29 35 21 57  AB E7 C2 CB  E2 CA 44 B6\n" +
      "     6F 1A 4B 08  33 C1 30 B8  5C 28 AD E3  79 75 C8 26\n" +
      "     44 70 C5 1A  83 A1 54 E1  4B 74 7B D2  23 AC E1 27\n" +
      "     4F 68 02 08  D0 7D 0C 6D  5B 1A 31 D2  72 BF 94 D7\n" +
      "     EC 70 20 BE  F1 5D 24 2B  E3 D8 0C C9  D9 E1 E4 AB\n" +
      "     F4 0D 31 19  97 22 91 EA  A5 DE C6 A2  E2 66 5E 03\n" +
      "     C5 BC DA F9  E9 AF F9 07  C8 A1 68 09  83 96 5A DE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     0 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     C8 87 70 87  DA 56 E0 72  87 0D AA 84  3F 17 6E 94\n" +
      "     53 11 59 29  09 4C 3A 40  C4 63 A1 96  C2 9B F7 BA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     1 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     C4 51 43 CC  B1 24 11 FE  AE 63 17 20  3D 67 D9 E0\n" +
      "     77 69 B8 F7  20 C8 AE F6  17 A6 9E 69  D1 67 9E 53\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     2 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     85 91 BE 2B  7A C2 89 42  E5 B8 D6 92  4D 4A 09 97\n" +
      "     D6 8E 34 30  12 98 E6 7D  F5 EE AB 6B  CF E0 0D 96\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     3 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     26 9B 99 A8  EC F4 BF FA  1C 05 24 4E  2B 8F 9A 5E\n" +
      "     74 5B 8D 47  A9 B5 A5 17  77 9F D8 29  7A 3F 8C 44\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     4 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     62 E6 E2 0A  A6 AB 34 3F  99 73 F0 61  10 45 BD C1\n" +
      "     E6 D1 CB AA  27 4A 7B A1  46 23 41 F4  95 33 B3 16\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     5 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     57 15 1F 10  D3 D4 96 9F  2D 3E 2C 93  E9 D7 EB 8E\n" +
      "     85 26 53 E7  D8 8B 60 10  4B 18 3C 7B  4E 5D 65 BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     6 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     76 24 DC F5  C1 86 34 05  CD E3 15 AC  07 94 1C 4D\n" +
      "     15 F1 4F 00  49 0B A3 9E  81 7A F1 8B  1C 5B EB A8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     7 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     24 36 18 CA  E4 CD BB 9A  F2 28 B8 C5  CE E9 D5 CF\n" +
      "     DB C4 56 65  6D 3C 26 4D  61 1A BC 19  4B 9E A4 C9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     8 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     0B 98 DC D1  98 EA 0E 50  A7 A2 44 C4  44 E2 5C 23\n" +
      "     DA 30 C1 0F  C9 A1 F2 70  A6 63 7F 1F  34 E6 7E D2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     9 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     3F 34 82 F7  78 88 DB 0E  E6 04 51 65  30 8A 47 48\n" +
      "     03 44 19 C8  C5 11 C4 94  AD 73 3D 4B  6F 7D 9D 11\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    10 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     52 38 6B D5  35 B0 57 66  AD 78 8E 6F  63 01 D2 D0\n" +
      "     20 70 E5 E1  F1 36 E7 18  B3 2F 29 C6  BE 69 8B 0E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    32 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC\n" +
      "Result:\n" +
      "     AF B9 2D 1E  32 FA 99 49  3D E9 27 6C  6C A5 28 CB\n" +
      "     6B 33 FF 0A  D2 00 F3 39  C0 78 10 02  A1 37 34 BF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    64 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8\n" +
      "Result:\n" +
      "     0B 5C A5 67  12 AC 0D 94  50 BD 83 98  47 9E 28 24\n" +
      "     6C 32 96 47  13 8D 2B DB  45 E1 63 77  8F 83 08 D4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   128 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "Result:\n" +
      "     53 40 3B 16  A2 93 10 4A  51 7B CC CD  D1 36 FF 71\n" +
      "     F5 84 F7 FF  B0 57 A8 49  13 3A F3 D2  50 02 A0 1D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   192 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8\n" +
      "Result:\n" +
      "     16 7D 17 E8  C2 06 EC 9A  30 D3 B7 09  CC 51 AD 33\n" +
      "     D0 CE 4F 8D  0A 34 34 E6  02 A8 3F 62  12 10 28 F4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   255 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     BC 66 4D 67  AB 9B 98 F1  59 3B 09 0A  E3 87 57 F4\n" +
      "     25 BD 2C D8  57 29 03 64  20 88 4E 7E  6E 78 CC 07\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   256 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     8D 0F A4 EF  77 7F D7 59  DF D4 04 4E  6F 6A 5A C3\n" +
      "     C7 74 AE C9  43 DC FC 07  92 7B 72 3B  5D BF 40 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   257 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF\n" +
      "Result:\n" +
      "     08 B1 03 AB  1E 01 50 37  9F 46 C4 B8  B1 84 1B 77\n" +
      "     90 65 46 46  AB 59 1F 12  BF C4 76 E0  EA B9 E3 5A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   384 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "Result:\n" +
      "     8A 48 42 D9  C1 E9 F2 4E  38 86 FC 0B  10 75 55 F9\n" +
      "     ED A8 19 77  07 74 9C EC  C7 77 24 02  B2 FE A0 C5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   511 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     6B 82 22 72  BD B3 2A C8  43 4D 53 D0  DC 1B F6 DF\n" +
      "     D4 40 FD C7  37 C0 9C 1A  16 CA DA 1B  4F 3A 25 FD\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   512 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     DF 28 E9 16  63 0D 0B 44  C4 A8 49 DC  9A 02 F0 7A\n" +
      "     07 CB 30 F7  32 31 82 56  B1 5D 86 5A  C4 AE 16 2F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   513 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF\n" +
      "Result:\n" +
      "     B3 38 C6 39  FA 42 E1 C8  F0 4B CF CD  44 25 2A 36\n" +
      "     FE F1 1E 0E  FE C4 59 61  29 1A 46 70  EB 0D 72 48\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   768 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "Result:\n" +
      "     66 D5 C6 CA  0F 70 84 5E  F6 01 EC CF  19 3D 1E CC\n" +
      "     C2 28 4D 03  B4 D2 46 10  92 85 21 44  8E 6C 4A 1B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1023 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     65 54 DC C8  98 1B 21 3B  1C 0D BD A1  40 2A 3F 25\n" +
      "     09 6C 85 A7  2D 94 EF 01  29 60 46 F7  8E 0B 96 54\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   160-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     1F D3 08 86  A2 C3 15 DE  86 F6 7F FE  66 ED DD CF\n" +
      "     73 BE 4F E4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   224-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     FA E2 43 AB  76 B4 14 FC  48 83 EE 73  10 2F DC F5\n" +
      "     1C 2D 74 B9  8D F1 85 A0  BE 90 45 F6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     18 0D E1 06  A7 04 01 BA  38 F2 59 7C  25 CB EF C7\n" +
      "     36 DF D8 8D  90 F2 D3 35  2E 0E B2 55  AF B6 DB 63\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   384-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     9A 94 71 5F  16 0B 78 15  45 BC 7F F2  54 C9 7C D6\n" +
      "     C1 4B A2 0C  94 E0 49 9B  FC A5 8A B0  CF E8 31 1E\n" +
      "     0B 85 87 01  4F 5C F0 1A  3B FE 4C D5  AE F8 EB 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   512-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     1A ED AB 6F  D2 8F D0 ED  62 B8 2A 6D  22 FA 3C 6A\n" +
      "     71 AF F4 92  05 74 A0 D9  0F 4D 90 A3  B6 FF 96 F4\n" +
      "     36 A0 AB DF  54 84 0F 33  6D F7 D7 90  A2 18 5F 61\n" +
      "     1E 46 3F 40  B3 40 BE 82  11 06 27 FB  25 B8 02 AF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1024-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     62 E9 A6 C7  46 E5 2E 6E  F8 2D 9E 48  EC EE 4B 96\n" +
      "     59 9A A4 9B  29 F6 4D 3A  6D 97 EB 81  DC F5 6D BE\n" +
      "     3C 70 81 36  5F 7D A9 5C  5C D0 79 5D  C8 6B AF A5\n" +
      "     3B DA 81 30  5C D9 B3 AA  6A 76 88 9D  D8 67 94 EC\n" +
      "     FA 7B D9 DD  F8 DB 98 19  B6 D4 AB D2  C1 E9 0B 33\n" +
      "     12 A7 8E 06  EE 67 A6 F0  7D C6 31 44  63 B6 C9 CA\n" +
      "     89 79 0F 17  57 3D 24 A8  B7 7E 03 CC  83 95 ED 74\n" +
      "     2C 80 B0 97  C3 D5 CD FE  22 6E 77 84  C9 DE E5 2C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   264-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     22 1B D0 20  EF 6A B4 6B  CF 8E 0E 90  64 B9 6C 71\n" +
      "     58 38 47 49  A6 FF 54 C9  75 9D E1 5E  68 9C FB 8C\n" +
      "     6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   520-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     06 0F CA 88  AD 85 DE 37  DA 1A 17 17  01 CE E2 62\n" +
      "     A3 43 BD DE  04 0D AC AA  0E ED A6 64  6E 0B DD 51\n" +
      "     2F A2 4D 9D  1F 0C CC 6B  D6 93 54 D3  46 B6 03 7E\n" +
      "     1B F0 33 2A  CD 14 E7 B2  00 CA 41 2E  09 E9 FE 79\n" +
      "     E7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1032-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     71 4E B7 5C  42 8E DF 27  E6 E2 2E 53  C4 C1 71 36\n" +
      "     BB 8D 40 94  68 DA 06 1B  41 32 5F 09  F2 32 89 C1\n" +
      "     07 B0 E4 00  AF 1C 12 A9  E1 56 A1 01  AD 2E A9 2A\n" +
      "     29 B4 70 DF  2A D3 5B 7D  7E 27 B7 C7  7E 30 2D AE\n" +
      "     4F 34 CE 0A  E7 72 54 82  C6 4A C3 D4  14 21 33 E1\n" +
      "     3A 92 4C B9  FB C2 E8 B8  95 5F 84 6E  E9 17 3F 77\n" +
      "     4E CE 4E 2D  1E 8E 5C 15  38 A4 C6 0A  AE 01 8D 6E\n" +
      "     71 13 9E 06  54 54 0F 9E  77 D6 01 49  E5 A6 2A 0D\n" +
      "     F0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  2056-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     B6 18 96 A9  C8 E9 39 F3  0B 55 48 11  22 17 32 17\n" +
      "     49 A1 FE 88  F3 B1 81 48  97 BC 5D 47  09 85 FF 50\n" +
      "     B6 F6 6B CF  73 AD 68 2B  49 7A E7 37  33 18 6A EA\n" +
      "     BF C1 93 8F  9B 43 8A F4  32 EF 91 DE  99 48 3F 3A\n" +
      "     B0 DC 71 B3  C9 09 31 1A  47 B6 DC 77  D9 74 DB 3A\n" +
      "     F6 83 47 0C  88 43 89 DB  6F A3 C2 19  D9 AD 82 2B\n" +
      "     09 E2 44 48  12 52 E4 DA  A9 CC CE 6A  3F 70 9C 57\n" +
      "     F3 55 3C 6D  94 1F 70 26  57 0A D5 74  E5 82 99 B1\n" +
      "     92 78 8C A8  76 05 D4 42  94 29 90 CC  88 35 AD 89\n" +
      "     DE A3 50 47  95 34 4B B2  38 A9 11 35  69 1A A7 70\n" +
      "     AE 6A DF E9  BC FC D6 C2  8C 78 0A 47  B7 8D 24 85\n" +
      "     65 CE 49 F6  C2 DF EC B8  D8 C2 A4 E8  95 84 5B ED\n" +
      "     0D C7 37 46  BD 56 A6 39  56 55 68 1C  DE 63 68 AA\n" +
      "     4C 58 03 29  BA F2 84 EF  B3 10 4E D4  98 4E 4B 07\n" +
      "     EA 8E 9C 78  FB 99 49 29  08 44 4F 4F  78 16 02 C3\n" +
      "     79 2A 9B B1  51 26 C2 DA  28 D9 39 0E  E5 6F F0 FC\n" +
      "     22\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1025 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F\n" +
      "Result:\n" +
      "     6F 6D B5 27  A6 05 8E FB  40 A8 1A EE  4B 5E 0A 3B\n" +
      "     B4 92 67 61  A4 7B 4D A9  BC 8B 15 5A  4A E7 08 91\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2047 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     36 A2 5D ED  A5 BA 34 CF  59 2F 25 12  D9 86 9F C1\n" +
      "     F1 7E 40 3E  66 80 3D AF  3A 49 20 25  FB 82 62 5A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2048 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     A0 88 EA C7  A7 25 6D F7  25 5E B5 73  37 79 26 7B\n" +
      "     5D D7 F8 64  32 0B AB 3A  B9 61 DA 5B  EE 23 CB 35\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2049 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "     FF\n" +
      "Result:\n" +
      "     D0 EF D8 F7  18 84 FB 74  8A B0 E5 05  42 1B 4E 4C\n" +
      "     55 7C 09 89  CD 28 6D C0  A6 D8 91 52  78 04 9E 78\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     0 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     BC 5B 4C 50  92 55 19 C2  90 CC 63 42  77 AE 3D 62\n" +
      "     57 21 23 95  CB A7 33 BB  AD 37 A4 AF  0F A0 6A F4\n" +
      "     1F CA 79 03  D0 65 64 FE  A7 A2 D3 73  0D BD B8 0C\n" +
      "     1F 85 56 2D  FC C0 70 33  4E A4 D1 D9  E7 2C BA 7A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     1 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     54 EA EA 3E  D9 F3 34 01  BA 8A F6 45  B3 D3 80 FC\n" +
      "     40 2E 61 B4  3B 84 ED 26  B3 D1 E9 80  72 A4 B0 29\n" +
      "     CA D8 6E DB  DC 17 34 3B  AD A6 27 0D  9E EB B0 44\n" +
      "     17 25 AF EA  51 AD 74 F0  43 CD 25 4B  BC CE 2C B7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     2 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     B0 55 F4 35  FF 61 15 13  2E F7 71 BF  F1 E3 82 04\n" +
      "     3D 93 BE 94  AD 3E 2E 17  15 E6 15 86  32 2C 5E 25\n" +
      "     99 C8 8B 1E  48 3C 22 2D  EB 44 86 68  C4 1C BD 48\n" +
      "     DE 27 03 93  1C 98 6D 3F  C0 D6 8F B9  00 87 E3 40\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     3 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     FC AB D6 46  33 C0 1B 1F  51 80 32 1C  3A 73 4D 37\n" +
      "     58 CB D7 35  FC 4A 77 F4  32 E2 D0 C9  9E 5A F2 8D\n" +
      "     AF 26 9D CC  B3 4A 74 35  E9 31 15 7E  49 B8 D2 E3\n" +
      "     EE D0 FC FA  B7 1F 16 33  D8 89 E6 54  28 D9 52 42\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     4 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     15 6E 61 BF  4C 11 04 6E  64 3B 86 86  C4 BD 85 B6\n" +
      "     C7 85 DD A5  B4 66 94 3D  DF D6 1E 4C  AC 05 EC CC\n" +
      "     B9 B8 2B 27  77 69 29 F4  A3 39 AD 7F  9A 39 91 AF\n" +
      "     E3 E4 9A 3A  40 7E 0E 7A  75 E5 92 87  DE F2 F8 99\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     5 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     18 5C 59 DC  2F 1B 49 D3  92 04 20 41  CC F8 C3 B2\n" +
      "     01 69 22 59  70 4A 90 F7  50 DA 33 DA  E8 E6 01 61\n" +
      "     9A 5E 7B CB  2A 72 31 97  D2 48 E8 05  AB 0F 20 9A\n" +
      "     34 01 FB 6F  B6 71 34 EE  3A 0F EC 77  F0 6F 41 6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     6 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     F1 55 57 F1  F8 37 E1 14  36 26 45 18  50 B9 35 45\n" +
      "     41 68 A3 4A  E0 A0 16 E5  BB AE EA 69  CE E2 F1 A5\n" +
      "     51 A1 BB 9D  F7 34 6E 5D  D1 58 D5 95  86 A0 1D 5B\n" +
      "     CC 04 D2 2E  43 88 B9 C3  65 0D 12 EB  5B 5C 10 8A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     7 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     5F 01 A2 C2  63 45 0D CB  F5 29 24 21  A9 D0 16 10\n" +
      "     6B 3E DD 0D  CF 79 61 41  DB CF 5D 5D  E3 A1 8E A9\n" +
      "     B6 65 07 DE  A4 78 4A 7C  19 7B D1 47  69 63 8D 56\n" +
      "     76 36 94 35  52 98 D3 0A  7D 45 77 72  9B F0 60 16\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     8 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     71 B7 BC E6  FE 64 52 22  7B 9C ED 60  14 24 9E 5B\n" +
      "     F9 A9 75 4C  3A D6 18 CC  C4 E0 AA E1  6B 31 6C C8\n" +
      "     CA 69 8D 86  43 07 ED 3E  80 B6 EF 15  70 81 2A C5\n" +
      "     27 2D C4 09  B5 A0 12 DF  2A 57 91 02  F3 40 61 7A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     9 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     F2 3B 93 DB  E9 A9 0B 29  EB E8 B1 FE  A0 D6 36 18\n" +
      "     2B D6 CA F4  16 92 F0 37  71 45 24 F4  EE 3D 76 7E\n" +
      "     B7 D6 8D 39  F4 3E B8 F1  F9 26 4F 34  F5 1F 17 A7\n" +
      "     95 90 6D D2  B6 18 3B 74  CB 75 E2 69  17 2D 4F 7D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    10 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     CE EC E7 DB  01 69 B2 F8  DA 4B 84 EF  7A CF 0C 47\n" +
      "     AA 6E C0 E2  34 32 E9 3B  C1 CA 60 D8  3A 87 69 C1\n" +
      "     9D 18 27 E5  DE 79 49 7F  A2 BD FA 16  92 2C AE 02\n" +
      "     09 88 EB D5  12 C3 FA 1F  5B 12 65 6B  C8 8C B3 3E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    32 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC\n" +
      "Result:\n" +
      "     19 D5 9A AC  61 1C 22 B8  49 A7 79 00  46 7C 2A 58\n" +
      "     B5 21 7C 5B  22 07 3C 95  18 27 88 B4  99 6E EB D5\n" +
      "     F9 23 E6 37  A2 95 A7 AD  2B 35 E8 48  7A 7C EF F9\n" +
      "     8B 23 CE 5A  52 11 D9 85  54 E6 38 13  C5 9F 84 06\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    64 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8\n" +
      "Result:\n" +
      "     D7 4B 91 50  06 1C 93 83  9B C3 59 2C  3A 58 7D EC\n" +
      "     86 1B D6 E2  4E 5E F8 92  88 B6 E9 9F  7E 0C A0 D2\n" +
      "     11 55 D4 18  5D 7F F6 AC  DC 71 06 99  9F 82 19 94\n" +
      "     5E 61 F4 01  79 6B EC E9  82 14 05 9F  A9 62 B3 73\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   128 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "Result:\n" +
      "     8E AF 7A FC  9E 85 A2 3F  4E 46 BA 4C  55 13 06 64\n" +
      "     09 A4 17 79  B4 71 AE 84  FA C5 F5 C0  D6 64 80 40\n" +
      "     E1 93 37 E3  67 AD C7 AB  1F AC 2C 78  D3 79 B6 36\n" +
      "     9D 90 5C D6  CD FA C2 B0  D9 8E 62 60  C4 71 93 F7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   192 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8\n" +
      "Result:\n" +
      "     B6 1A 89 1E  0C CF 17 9E  4E A8 73 E6  85 15 AF F6\n" +
      "     A5 E4 C2 A1  9F ED 7F 02  B1 A9 1C 0F  97 81 AE 9D\n" +
      "     EA E4 AA 96  96 8D 54 4F  F9 F9 D9 3B  55 CC 40 49\n" +
      "     88 EF E5 8F  0E FF 0D AB  B1 BD 2D 3C  8B 8D 46 7C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   255 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     6A 49 E9 21  03 3F 64 8D  4F A8 50 ED  8C 79 C5 4A\n" +
      "     D3 CB 06 32  96 AE 70 5C  E1 41 39 04  31 2B A0 80\n" +
      "     DE 38 7C B8  C8 CC 97 BE  55 58 29 D0  DF 9D CC 4E\n" +
      "     B2 62 99 B3  67 83 4C 85  10 7A 81 E0  7E F6 60 CF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   256 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     0B 7F D0 53  AE 63 5E E8  E5 19 64 6E  B4 1E A0 CF\n" +
      "     7E A3 40 15  23 78 06 2F  B2 44 0A A0  25 0F F1 95\n" +
      "     FE 32 D9 A0  69 1E 68 A0  FE B1 7D C2  85 AA 67 56\n" +
      "     CE F1 94 04  E4 DB 92 BF  83 6C 4A E6  53 81 50 4A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   257 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF\n" +
      "Result:\n" +
      "     AF 0C D5 66  DE B1 85 FD  0D 8C 95 8F  59 9D 4A 3D\n" +
      "     EB D0 A6 CE  D1 33 37 AE  12 7A E0 FA  C2 4F 8A 2C\n" +
      "     E1 1D 11 FE  FA 77 46 B0  0B 5B FA EB  FD 0C 1B 54\n" +
      "     E8 59 65 22  EA 11 60 93  7F E2 2C C2  A7 F0 28 70\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   384 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "Result:\n" +
      "     8E 48 B8 56  16 54 91 8A  72 E3 91 97  6B A9 75 DD\n" +
      "     31 5F 25 1F  CA BF 2D 4E  23 2E 59 50  FD 9E 67 DB\n" +
      "     6E 88 BE 25  92 0C B6 5E  D0 AB A5 A4  D3 1B 08 06\n" +
      "     2C 68 88 EB  63 99 7A 17  6C E2 70 D0  5D F3 93 75\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   511 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     75 FA D5 6F  1C BE 41 51  CA DC F9 B7  C0 34 D8 B8\n" +
      "     40 91 0B 46  A6 2B CF 26  62 67 CB C4  9D EC C2 3A\n" +
      "     AB 50 FC 37  5B 8C D0 5A  16 32 91 95  17 05 31 77\n" +
      "     4F 17 46 E1  F1 F5 DB 78  F4 DC DD 12  10 AE 0E 69\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   512 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     45 86 3B A3  BE 0C 4D FC  27 E7 5D 35  84 96 F4 AC\n" +
      "     9A 73 6A 50  5D 93 13 B4  2B 2F 5E AD  A7 9F C1 7F\n" +
      "     63 86 1E 94  7A FB 1D 05  6A A1 99 57  5A D3 F8 C9\n" +
      "     A3 CC 17 80  B5 E5 FA 4C  AE 05 0E 98  98 76 62 5B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   513 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF\n" +
      "Result:\n" +
      "     38 E8 A3 4D  90 A2 44 A6  D7 3F A6 A8  EC D5 E9 93\n" +
      "     D1 AD D4 BB  CB E3 D4 35  C8 FC EC 4B  39 7C 12 A8\n" +
      "     38 A3 CD A4  58 6B AF B0  67 EB E8 D0  10 ED 02 FE\n" +
      "     BF F4 2D F2  A9 49 DF 03  0C FA 4C 78  0C 23 B2 34\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   768 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "Result:\n" +
      "     AC 8C 00 26  1D 7A 5A 79  CD 69 B5 AF  12 8D 77 EA\n" +
      "     4E 60 0C 7A  82 52 C6 CC  1A DF 7D BC  95 72 C1 C6\n" +
      "     13 C0 C9 0C  D3 DD 87 A5  49 53 CB 87  96 20 9C 94\n" +
      "     C0 16 5E E1  B3 CA 37 34  FF E3 6D D5  9E 3A 03 A4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1023 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     37 A1 B5 B5  14 41 15 A4  A5 8F 5D CA  9B 24 C5 3D\n" +
      "     2C A1 9D 18  2E 15 E4 76  0B 1C C1 69  EF EE 05 AC\n" +
      "     F0 AA BC 07  70 8F 81 75  57 A9 0C 13  7C 44 54 A3\n" +
      "     23 FE BA A4  2F 97 DE 84  68 65 39 0D  2E 71 C4 C3\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   160-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     7D 59 D2 3F  CF 38 FF 54  71 0F 0D 38  D3 A0 AC CE\n" +
      "     7B 8D 64 F6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   224-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     21 52 1B 15  C8 A9 F0 5D  59 58 F9 97  00 8E 95 C5\n" +
      "     0C 4E EE 35  FB 30 BA 81  D5 83 18 56\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   256-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     1A 6A 5B A0  8E 74 A8 64  B5 CB 05 2C  FB 9B 2F A1\n" +
      "     28 20 32 30  A4 D9 92 3A  32 9F 54 27  C4 77 A4 DB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   384-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     EE AF 4D C9  B6 68 C2 A2  70 B9 0C BD  2E 98 6C 85\n" +
      "     7E 46 4B 08  90 3E 5B 6D  DA 1F 15 73  6F 50 D1 BF\n" +
      "     2B 6C 40 A3  98 B7 9C 67  53 35 92 EF  D9 6B D8 DC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     91 CC A5 10  C2 63 C4 DD  D0 10 53 0A  33 07 33 09\n" +
      "     62 86 31 F3  08 74 7E 1B  CB AA 90 E4  51 CA B9 2E\n" +
      "     51 88 08 7A  F4 18 87 73  A3 32 30 3E  66 67 A7 A2\n" +
      "     10 85 6F 74  21 39 00 00  71 F4 8E 8B  A2 A5 AD B7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1024-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     BE 71 89 13  53 E1 57 D8  55 70 07 E6  C4 DB 77 42\n" +
      "     A8 E9 4D 26  77 B8 BF 13  8E 0E 74 7D  4F 70 24 BA\n" +
      "     5E 9D 53 1D  B0 B6 CB 41  26 77 68 5B  9F 9B 0A 7F\n" +
      "     CD 42 99 C5  D5 08 51 25  34 7B 59 A4  7B EA FD 6B\n" +
      "     D2 D7 C9 DE  07 CC E0 77  01 C5 D0 CE  3C 3A 8F 75\n" +
      "     E0 A8 C1 6E  1A AD B2 92  98 21 99 69  DA 77 C5 2C\n" +
      "     BF 8D D8 CF  86 A9 E1 B0  BB 7D 18 15  3D 70 EE 5C\n" +
      "     26 60 6D 92  2D 91 5C 05  DA 41 D6 4F  DE B4 21 50\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   264-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     7C FE EF 0B  AE 71 26 20  48 0E F2 72  88 08 C9 B5\n" +
      "     9F EE D9 8A  DA 3C 0D 6F  CF 89 4B 05  1F FB 50 2B\n" +
      "     F4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   520-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     9E 65 5B 72  5A C0 96 43  C4 49 C7 24  C6 B1 19 7D\n" +
      "     DC F7 D4 2B  8B C9 EF 80  47 63 0A B3  84 8C 39 C7\n" +
      "     8E E5 F0 60  F7 01 86 39  E2 02 01 C7  D8 6E EF E9\n" +
      "     84 52 D7 CF  C2 43 5E DE  CA 9A 4E 1A  EC 3E 9D C9\n" +
      "     3F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1032-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     23 B7 D7 8C  BB 97 69 BD  23 B0 86 75  BD 87 F2 C7\n" +
      "     AF 44 47 04  72 8A 1A F4  C8 5F E1 C0  84 9D BA 48\n" +
      "     B3 6C 87 39  D2 41 A2 C6  D9 63 E7 E8  40 1B 8C E3\n" +
      "     C9 BC 2F 1D  4F 93 69 98  85 B5 34 39  B9 06 AC EB\n" +
      "     2E 9D 9B 11  56 E9 7E 3D  9B 9E 8E A9  46 88 D2 E5\n" +
      "     F5 D9 9C 4C  64 19 67 C9  C0 26 ED F3  F9 E1 25 97\n" +
      "     6E 1B 30 05  31 7B BE BC  84 A4 C1 A0  F6 4C 76 1C\n" +
      "     F8 69 66 0C  C1 8D 3B A7  0F 8D B9 5E  E5 F6 17 0B\n" +
      "     16\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  2056-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     49 16 E1 18  DC 63 C5 1A  A2 DE AE 18  C5 C6 36 8F\n" +
      "     17 44 41 D9  F3 B8 78 80  51 5B 9D 2B  CD EE 3A C8\n" +
      "     B2 89 F5 65  37 E1 EC 1C  A2 52 08 76  2D 1D 5B 16\n" +
      "     CC 0D A2 D5  28 03 81 5E  6B FB FC 28  DA FD EA E0\n" +
      "     8C 67 98 DF  B9 40 90 2E  C0 0D B4 5C  19 9E 90 A2\n" +
      "     0D FA FB D3  6A 1B C3 1C  BC 5B 87 B6  3C F2 57 EA\n" +
      "     3B 68 DF 86  65 39 AF 09  B1 29 1D 24  C7 48 AB 2A\n" +
      "     3E 4F 34 7D  58 E5 1B C2  17 30 10 FF  73 F4 4F 6F\n" +
      "     58 36 6D 8A  DB 90 82 95  6D 99 26 A8  E8 0E EC B2\n" +
      "     BF 4B 79 3F  FB 31 EF D3  E1 46 CC 4E  14 DD 9F 34\n" +
      "     D1 18 37 09  AF 9F D3 67  CA 45 B7 D8  98 F5 28 D5\n" +
      "     21 E1 F3 AB  E0 D3 EE 51  01 9D E2 4E  63 C9 4A 7E\n" +
      "     51 27 53 3D  7A 47 BE AB  CC F6 93 97  5E F5 94 96\n" +
      "     74 07 32 2C  FE 13 2F 31  BA C4 11 16  FA 6B D4 45\n" +
      "     38 14 39 0A  02 88 D3 25  45 63 86 98  A5 EF B0 C2\n" +
      "     83 A7 55 A4  34 55 F9 7E  73 6D 1A 2B  C8 0E 59 4D\n" +
      "     21\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1025 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F\n" +
      "Result:\n" +
      "     DB 70 D7 31  CB 54 F2 73  E5 09 B1 7C  F3 8A 90 29\n" +
      "     E7 48 51 A3  E1 33 5D D9  2E 93 A7 19  0E BB AB 55\n" +
      "     04 EE 5D D5  C1 5D FA DB  64 60 91 2D  CB 8D C1 83\n" +
      "     72 F5 62 C8  61 47 7F 9C  43 CD DF 0F  6D 91 0E E1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2047 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     BC 23 D9 21  8B 8A 18 58  D6 D3 47 FC  3C D6 D2 28\n" +
      "     ED A4 F6 34  7F FF FF 93  EE 55 7C 59  2B 6F 42 CD\n" +
      "     B3 BB E4 61  DB 3C D3 74  EB F5 DA 6D  62 85 27 9A\n" +
      "     2E 2A 21 E9  0E 37 9F B9  6B E2 19 6B  17 7D AA 5F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2048 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     A5 5C DA 09  FC 2D FB 35  CC 20 C1 C5  8D 8B 00 CC\n" +
      "     68 F3 1D 26  D5 53 85 D8  FC 7A C2 A4  FC CD 45 22\n" +
      "     1F EF 7C 1D  18 A9 00 B7  5A 22 14 EE  6F 07 EF 4E\n" +
      "     5D 03 A3 E9  D7 29 4B 1A  5F A6 E3 42  EE C0 05 58\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2049 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "     FF\n" +
      "Result:\n" +
      "     DA 80 0C B7  60 50 58 B2  C4 C3 19 65  5B 14 CC 4B\n" +
      "     69 27 D8 96  C8 4B 5D 3A  8B 79 51 D9  8F 35 6E BF\n" +
      "     38 36 BF AF  73 8E 5E B5  05 FA 5F 64  1A 21 C9 13\n" +
      "     BD EA BD F4  E3 88 B3 A2  22 BA FA 9F  D5 7A 62 FD\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     0 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     0F FF 95 63  BB 32 79 28  92 27 AC 77  D3 19 B6 FF\n" +
      "     F8 D7 E9 F0  9D A1 24 7B  72 A0 A2 65  CD 6D 2A 62\n" +
      "     64 5A D5 47  ED 81 93 DB  48 CF F8 47  C0 64 94 A0\n" +
      "     3F 55 66 6D  3B 47 EB 4C  20 45 6C 93  73 C8 62 97\n" +
      "     D6 30 D5 57  8E BD 34 CB  40 99 15 78  F9 F5 2B 18\n" +
      "     00 3E FA 35  D3 DA 65 53  FF 35 DB 91  B8 1A B8 90\n" +
      "     BE C1 B1 89  B7 F5 2C B2  A7 83 EB B7  D8 23 D7 25\n" +
      "     B0 B4 A7 1F  68 24 E8 8F  68 F9 82 EE  FC 6D 19 C6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     1 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     47 28 53 70  0A 4E B0 C7  28 CC 3A E7  84 A6 AE C9\n" +
      "     CA FE 79 47  D7 E0 25 71  43 8D AF A5  0B D6 48 EC\n" +
      "     FC 4A AD C1  E4 8A EF EF  71 78 33 0F  DE 72 53 94\n" +
      "     C8 EC BC B4  8F 94 BC 4D  9F E6 02 AB  AF 5A 36 B2\n" +
      "     8F 27 2A 58  E0 3E 61 C9  4B F8 9C FE  E2 7A D2 9D\n" +
      "     8D 94 54 EE  7A 91 83 84  54 38 26 47  D0 ED 8D BA\n" +
      "     1B CF 6C 95  97 3E 7C 5B  45 D2 22 82  78 AB 4E 5A\n" +
      "     72 22 A5 C8  E2 41 43 F8  1D D6 EF 30  0D A8 8A BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     2 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     11 42 5D 06  3A B0 3D BE  12 2A 4D B2  33 ED C0 38\n" +
      "     15 38 67 D4  84 1A AB 3E  09 17 B8 1F  C5 80 59 CA\n" +
      "     92 8B D1 5E  0D D1 D0 80  AB D3 33 04  D7 B8 0B F9\n" +
      "     FF 12 CE 39  1D 2D 13 C2  58 FF FC 3B  62 01 1B 47\n" +
      "     F6 82 F4 4B  10 B4 E5 90  92 A9 07 C7  63 D3 A8 66\n" +
      "     99 48 50 C9  E0 DD C2 40  05 99 70 0D  94 2B D4 91\n" +
      "     3F D7 38 E7  1B 55 D7 9A  03 02 76 74  CE FF 3F 1B\n" +
      "     89 9B 66 74  F4 21 C0 B7  EE 43 CF 00  9D F6 DC EA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     3 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     2C 6B 60 FA  31 1B 79 21  D4 4D DC 99  AB CD 91 AA\n" +
      "     29 93 43 2F  9B 14 92 8C  E6 31 06 B5  FC 37 60 8D\n" +
      "     1B 12 E7 EF  AD 2E 76 93  7C A7 7B B5  AB B8 28 B3\n" +
      "     BC 21 23 FE  AA 49 F8 00  26 F4 E3 6F  88 CD AD 10\n" +
      "     A2 83 AA 28  2E 09 D0 26  24 E9 BD 58  6D 4C C6 A0\n" +
      "     F8 C9 0A 21  83 AF B7 1C  DA A1 5A D0  58 84 5E 20\n" +
      "     7B EB 12 A8  5C 3A 17 3A  61 69 48 FD  99 91 5B 69\n" +
      "     35 C0 76 8B  23 D9 7C 0B  A5 2A F9 85  E0 7B 87 AF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     4 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     FC CA 16 4A  E7 D8 51 AC  E6 F3 99 CB  AB A4 09 FD\n" +
      "     50 4C 43 52  C3 71 E0 7B  3E 19 B3 B2  6C 14 97 DD\n" +
      "     27 FA 78 78  ED 26 4D C3  AA 09 78 91  8A 69 4F 44\n" +
      "     AE 1E 78 8C  B1 27 BF 82  09 72 00 BC  48 1B 47 AD\n" +
      "     02 BD 56 73  6A 6A 5A BE  C2 A4 D8 AD  64 8A 9C BC\n" +
      "     13 AD FD BC  1F 8F D1 51  B8 88 F9 FF  A1 38 7D B6\n" +
      "     48 8B 1E 94  CB 4C D1 69  0D B2 DC 5C  8F 9D 89 99\n" +
      "     C4 22 3F 74  F7 29 AA 36  19 D8 45 AB  0A 37 F9 50\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     5 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     0B B6 A8 33  4D F7 3C 46  09 24 B4 FB  20 40 19 56\n" +
      "     73 A7 F0 86  08 16 A3 2A  93 9A C0 77  24 61 DD 20\n" +
      "     E0 68 A3 A5  29 77 94 13  9A 9D 68 9B  91 22 A1 44\n" +
      "     82 BD EA 22  4C B1 D6 88  95 A0 07 80  BF 55 46 BD\n" +
      "     B6 DF 01 BB  16 CA C2 5F  1B 0B F3 62  E6 B4 5B 01\n" +
      "     F9 E4 E8 97  E4 60 CB 04  49 32 51 79  7B 65 48 FE\n" +
      "     1C 97 48 ED  6C A5 52 62  36 68 A8 2E  0B A5 2C 5E\n" +
      "     9A 99 F7 04  55 BC 12 76  10 86 DC A3  A5 30 59 EB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     6 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     65 57 C3 70  F2 6F 79 72  05 1D BC 39  21 E8 44 0C\n" +
      "     F1 74 4C 48  2E DE 6C EB  96 A2 0B 2B  37 3B D1 27\n" +
      "     2B A7 89 F3  3F 75 1F CD  B9 2C 77 C1  6C B7 38 16\n" +
      "     3C FB 40 39  73 08 7A 62  63 BA AC B3  CB 69 9D A6\n" +
      "     CB 6D 56 CB  1B 1F 75 93  D3 00 31 72  97 E0 C0 C3\n" +
      "     67 78 7A 75  DA 86 E0 66  58 D8 53 F3  15 88 8C F7\n" +
      "     C4 B6 EE DF  B2 3E E0 36  F8 4A 07 F3  56 E2 86 95\n" +
      "     73 F0 FB 66  21 89 00 85  EF 7E FC 6D  95 BA 3A C5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     7 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     EF 00 0C B5  56 28 54 14  29 B3 D9 F2  8A 3D 43 62\n" +
      "     D2 DA 41 4E  C0 24 8E 76  4B 5B 34 57  B1 3A 88 50\n" +
      "     04 6A 69 5F  6A F6 C8 07  73 D8 36 2C  A9 84 A7 64\n" +
      "     78 0F 99 A2  73 1F 40 98  B2 CD D4 15  07 03 2F 8A\n" +
      "     96 20 B0 69  CC CF 61 59  B8 29 5E 9C  56 60 E3 20\n" +
      "     D7 77 79 C4  21 B5 22 30  FF 14 9F 03  D2 1F B3 13\n" +
      "     7E F6 7C 75  EA 4C 9D 5A  DC F9 BD 42  A0 7B 7F 61\n" +
      "     4B E7 2E C4  1E 77 CF F0  E4 BB 2A 68  32 AA E9 A2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     8 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF\n" +
      "Result:\n" +
      "     E6 2C 05 80  2E A0 15 24  07 CD D8 78  7F DA 9E 35\n" +
      "     70 3D E8 62  A4 FB C1 19  CF F8 59 0A  FE 79 25 0B\n" +
      "     CC C8 B3 FA  F1 BD 24 22  AB 5C 0D 26  3F B2 F8 AF\n" +
      "     B3 F7 96 F0  48 00 03 81  53 1B 6F 00  D8 51 61 BC\n" +
      "     0F FF 4B EF  24 86 B1 EB  CD 37 73 FA  BF 50 AD 4A\n" +
      "     D5 63 9A F9  04 0E 3F 29  C6 C9 31 30  1B F7 98 32\n" +
      "     E9 DA 09 85  7E 83 1E 82  EF 8B 46 91  C2 35 65 65\n" +
      "     15 D4 37 D2  BD A3 3B CE  C0 01 C6 7F  FD E1 5B A8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     9 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     7E BB 72 1C  C4 57 C7 85  E8 8F FF 59  D0 13 60 85\n" +
      "     77 5C 76 66  13 0C F7 C0  D2 B1 B1 6F  F1 95 4A 27\n" +
      "     92 D6 1F F5  CF 2C 5A 46  1A 10 97 0F  99 98 61 E3\n" +
      "     3A FE 92 14  DF DE 3F AA  7A 77 25 D6  B3 4F 62 F8\n" +
      "     C7 38 66 EE  FB 6F FC 95  22 85 6D C0  6C 80 5E 8B\n" +
      "     64 38 42 55  25 EF 28 61  22 B8 3C E9  B8 9E 99 5C\n" +
      "     A9 D0 50 EC  C2 EA C1 49  24 08 AE C8  4A 6A 16 30\n" +
      "     91 54 3B 6E  BE C3 E6 11  77 EA 21 D0  39 2C E6 25\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    10 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE\n" +
      "Result:\n" +
      "     BF 8C E8 89  A9 DC 88 90  40 2D 56 99  A3 3A EE 4F\n" +
      "     CD EC F2 C9  BA 8A 7C 64  F7 FE 05 8D  38 4A BA 4C\n" +
      "     F7 AE 5D 29  A4 22 C4 F4  4B 51 8A AE  74 D0 B6 6B\n" +
      "     39 0D DF F7  D7 03 57 68  01 FF 49 CC  68 02 A1 0C\n" +
      "     8F 8C DC A0  4A 79 74 A9  E5 95 DA 8C  A6 7F 0D 34\n" +
      "     A8 28 29 F1  12 62 E6 B7  30 8D 97 65  C7 0D 0D 30\n" +
      "     9D 90 8E C2  3C 52 AA FA  84 6B 12 EC  13 12 87 79\n" +
      "     F2 FC E1 5A  C5 FD 36 76  7D 6E 28 EA  CB 45 19 A7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    32 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC\n" +
      "Result:\n" +
      "     F8 77 17 08  6D 37 BE 00  FA 04 50 48  F1 BF EC C8\n" +
      "     CE 78 59 EE  A8 50 B0 6D  38 11 48 94  9D 82 AC D7\n" +
      "     A3 6F 5E F5  FD 41 E4 06  8B 7C D5 CE  87 0E 4B 58\n" +
      "     9D 2B DA 4B  B2 0A DF 82  8E 93 E5 3F  BB 3E F4 86\n" +
      "     D2 D0 AC CC  3E 1C 94 F7  36 EE AD 1A  2E A2 E1 A0\n" +
      "     4D 08 1D 54  58 C3 FE D1  0C 8D B4 A2  39 82 C3 16\n" +
      "     73 F0 CB 37  59 5F 16 4B  C1 3E 97 61  00 23 6B 03\n" +
      "     45 F1 E1 62  D1 75 61 F2  05 B7 E6 D2  E4 FD 9B F0\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    64 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8\n" +
      "Result:\n" +
      "     AF CA E6 32  CB CD DE 0F  98 E6 E0 C0  2F 97 AA 12\n" +
      "     90 33 04 2D  55 77 66 E8  31 9D 0F 1E  48 83 9C 38\n" +
      "     BC 43 64 E2  34 E7 8B C9  7B C5 8D 11  03 6E CB 89\n" +
      "     40 90 09 3F  A3 48 C7 35  0A 78 B8 A4  0C 22 81 53\n" +
      "     3C 8A A8 E4  EB F7 3A 2E  5D 98 AD 05  8C BD 8A 18\n" +
      "     FE 4E 05 56  4B 00 02 D9  B0 67 2D 23  88 43 D6 4F\n" +
      "     24 91 C0 2C  5D A2 60 49  B0 BD 43 67  7A BE 40 2B\n" +
      "     5C 23 96 57  F6 B7 6C B8  4A 5B 30 C0  9D 85 D8 BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   128 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "Result:\n" +
      "     D7 36 BD 0E  3A 4E DA EF  F1 3D 26 3C  F2 78 4A 25\n" +
      "     AA B0 CD 6A  1E FE 45 32  06 D7 28 FF  FD 93 AE 8D\n" +
      "     1E 0E 46 34  FF DE BE 56  7C AE DE 2B  25 34 6F 62\n" +
      "     1A 38 69 A4  0F 7C 68 A7  9F 2F 82 B6  37 85 18 54\n" +
      "     41 40 DC 2F  1E 5D E3 07  4D E7 4D A4  35 38 A8 1D\n" +
      "     71 17 15 B2  D2 16 62 33  2B 33 C9 4C  C5 F4 E7 A0\n" +
      "     E9 CF 94 D0  F5 1D 1F C3  33 17 34 0D  2E 4D 2D 1A\n" +
      "     B2 E7 5A 81  5E 6F 0B EE  19 94 B7 60  8F 43 2E 2E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   192 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8\n" +
      "Result:\n" +
      "     92 E1 A3 B1  D8 A3 0E 35  9A 93 81 00  68 B2 10 72\n" +
      "     7C 5A 92 46  C2 DA E3 75  19 A2 63 26  6B 23 D7 E7\n" +
      "     BF EF 81 16  89 DE E7 5E  93 7E D4 D3  E8 97 D9 2A\n" +
      "     3C 46 23 90  4B F9 04 FE  65 8D 61 83  82 67 1A 06\n" +
      "     E8 38 C4 2E  2C 87 B8 E1  D1 2F 70 73  CF 02 C9 5C\n" +
      "     B4 9B C0 BE  2B 4F A0 6B  C2 77 5E 62  C4 48 76 C7\n" +
      "     30 EF D8 05  98 50 9F 6D  BA 83 3D B1  D1 7D 1F 03\n" +
      "     E8 E5 F4 8C  33 B3 25 7E  5C 08 93 EA  8A 83 CE 0C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   255 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     66 E9 14 15  F6 B5 12 01  F3 04 28 CD  21 E4 F5 41\n" +
      "     F6 8B 8E 02  BC 7B 1D 50  AA 30 90 77  06 0F 99 9F\n" +
      "     31 1D 75 8D  EF 4D 40 46  28 79 46 B4  25 C9 4B D1\n" +
      "     AD 53 F9 38  46 A8 31 F3  35 CE 60 6B  7E AE 72 9B\n" +
      "     49 8F F9 5D  7F 9C 06 6A  3E 54 9D 2A  A5 FB AB 80\n" +
      "     92 80 C8 AF  DB 6F E1 B7  75 C3 31 83  32 2F FB E7\n" +
      "     F5 D7 FE 83  EA 3D 05 E3  16 D1 36 12  C8 4F 08 0C\n" +
      "     BB F8 C2 DE  CD 45 DE 0F  8B 91 A3 63  9F 26 4E 1D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   256 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "Result:\n" +
      "     D9 F3 81 EA  AD A5 7D 8F  40 7A 01 D8  76 E6 B3 C2\n" +
      "     09 34 18 A4  86 04 5F 7C  E2 3A 90 15  0D 93 16 01\n" +
      "     3B B5 4E 56  38 B3 72 E3  75 59 72 89  CF 74 50 EB\n" +
      "     47 89 B5 55  3E 2B 29 47  D2 AA 81 09  7F 4A 8E 84\n" +
      "     D3 9E 0F CA  2F 30 B5 EE  7A 8E D7 3C  31 F7 8B 58\n" +
      "     04 B6 EF 79  F5 7F E4 43  AF BA 11 51  CC 48 E0 19\n" +
      "     1A C6 25 E9  D5 F7 2B 84  3D 77 10 B2  9E 7F 98 9D\n" +
      "     8D 3F C2 1B  BA 49 D4 6B  9F 75 A0 7B  22 08 67 3C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   257 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF\n" +
      "Result:\n" +
      "     B9 46 AC C6  A2 FF CE E4  C9 C5 17 15  71 FB 04 22\n" +
      "     15 2B 5C 62  71 F5 E0 13  42 89 A1 EA  4D 2D 2A D2\n" +
      "     78 94 24 EC  7A F8 1C E7  72 E0 A8 6F  C8 DF ED 70\n" +
      "     18 2A 7C 81  C5 57 E0 33  C0 D4 7A 5B  B5 2E EE E3\n" +
      "     88 75 57 CE  EA 31 E9 26  AC 72 1D 8D  81 F7 A4 05\n" +
      "     47 86 05 D3  B3 B4 86 3C  8D B4 DD B5  EB 6E FF 79\n" +
      "     09 C6 36 61  F6 5D 3C 5B  DF 1A 1D AB  E2 82 3F E9\n" +
      "     70 7B AF B4  B5 59 82 74  34 0E 39 D2  DC A2 54 91\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   384 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "Result:\n" +
      "     B5 F8 F1 CE  3E 04 D0 90  7D 64 AD E6  41 D6 F4 E7\n" +
      "     91 5A D7 74  58 24 02 1F  7C 68 F9 92  58 B8 42 50\n" +
      "     22 B6 99 48  5A 0E 7C 40  5D 6F 5A 8F  4D 87 1B 21\n" +
      "     15 E6 74 AE  D0 7E 19 D6  42 8F A2 F0  5A 46 87 F7\n" +
      "     1F B5 A4 92  C6 33 41 DC  ED D7 CA 9E  66 9D 95 74\n" +
      "     9D B7 5F E0  2C BF CD 0E  7E 0B E5 4B  3A FA AD 5A\n" +
      "     28 3C 35 63  41 51 AF AE  A1 F0 85 9F  D0 3B 2A 4C\n" +
      "     65 9E 2F D2  16 CE D2 58  DD 3C D3 78  1C 7C FA A2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   511 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     DF 39 A1 37  70 93 C0 DF  25 E9 4E 6E  D6 EA B1 9C\n" +
      "     37 04 8F 12  CF 17 A0 DE  91 7A 27 3A  3F E7 FA 09\n" +
      "     F3 CE D7 7E  E3 10 3F 73  3F 1B A2 09  27 ED 50 C2\n" +
      "     3C BB 8A A2  2D 2F 3C 3E  25 9B 6E A1  3D 42 B1 09\n" +
      "     B4 84 90 34  A7 4C 24 16  C6 33 4D 0D  11 7C 4F 3D\n" +
      "     58 DB 5F 5B  B9 A7 94 BF  27 85 E9 23  12 25 19 CE\n" +
      "     C9 7F 58 47  E7 B3 B0 D3  EA 9F 27 FD  22 33 2B 87\n" +
      "     BF 27 3E BF  AD 1B 80 A2  A2 C7 42 D3  C9 02 A2 D4\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   512 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "Result:\n" +
      "     0E 10 EF DC  94 5E BE 7D  7C F0 07 3A  90 2D 9A 5B\n" +
      "     C0 D9 95 66  F7 FE AE D8  65 84 C6 53  B5 0F 71 CA\n" +
      "     8B FC 50 1E  3D 26 E0 14  05 88 DE 50  E9 FB 2B 01\n" +
      "     99 BF B4 18  95 D7 E3 33  86 B2 CC EE  46 CF 32 0E\n" +
      "     38 4E AB B0  8C F4 16 22  1D 22 88 C5  8D 34 3F A3\n" +
      "     BA 66 F4 DE  ED EE 93 3F  A8 9A 58 4D  EE A3 22 84\n" +
      "     11 AE EB 7F  56 4B BB DB  31 D1 FB 61  F2 DA 95 A7\n" +
      "     43 2B B5 21  4E 4A 95 EB  16 0F 9A DF  20 A5 E8 06\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   513 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF\n" +
      "Result:\n" +
      "     ED A8 CD C0  4A 1C 45 A9  F9 7E E4 FC  76 28 86 BC\n" +
      "     83 13 0A 81  1D 84 7B 20  BA 4E 4A F9  00 9C 70 EA\n" +
      "     9B 37 EA D9  F7 BF 32 1F  BE 3A 67 53  DF CC 09 21\n" +
      "     DF 3C 2F 49  58 2F F1 37  E3 F9 5C A1  6C FB 25 78\n" +
      "     21 6E 4D 42  B0 5F 14 86  7A 42 4D A7  A3 ED C9 5B\n" +
      "     67 D4 4D 78  8B D7 F8 4A  CB 0A 66 04  56 20 45 A4\n" +
      "     52 9F CC 7F  20 9E 11 F1  9E 16 FA 34  48 B1 5C A0\n" +
      "     4F 37 43 CE  29 B4 CC 86  18 B0 4C EF  2D C8 4C A2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   768 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "Result:\n" +
      "     DE 3E 11 3A  97 F0 83 BF  73 8A 88 8B  97 4D 11 DE\n" +
      "     BC F1 10 C0  A7 EE B6 C1  10 B3 D8 16  B8 92 50 B3\n" +
      "     2D 1A C2 15  60 08 92 7D  4E E8 B7 E1  A1 83 31 7B\n" +
      "     2E EB 85 0F  05 BC 86 82  A0 32 D4 28  85 08 A4 8D\n" +
      "     6B 17 0A 81  9B 14 CB A9  8D 86 5B A7  91 9E 2C 27\n" +
      "     F4 62 7A D5  41 2F 52 4B  9D E6 D7 0A  C7 9F 5C 3E\n" +
      "     FB B2 A2 AB  A4 AC 9E EE  CD EF D3 37  E2 EC 9E 5D\n" +
      "     3A 17 02 73  BB 47 66 FB  3E D0 14 79  F7 8D 63 AC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1023 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     DD C4 A7 03  FE A6 66 F9  D2 8F CE 82  A6 FD 7F E1\n" +
      "     8D D0 1B 3A  79 B2 64 DA  86 B0 5E ED  69 1A B7 22\n" +
      "     61 E6 10 E5  85 AA BB 63  93 20 97 11  94 D8 14 1B\n" +
      "     79 A1 94 08  3E BB 6F 96  C2 86 4F 65  7A 31 4F F9\n" +
      "     C7 42 E4 2E  19 20 C0 EC  C8 F9 86 5A  3F 94 F7 FE\n" +
      "     A9 40 9F B2  00 71 E2 18  46 02 05 DB  4A 0A B0 99\n" +
      "     E0 52 3B 6D  A0 C8 64 47  F6 BF 95 C2  86 DE 91 AB\n" +
      "     F3 03 8F 09  D7 2B 53 A6  20 6B 1A 02  37 AA 3D 92\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  160-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     79 91 DB 03  AC B0 8B AF  48 27 15 46  A6 83 67 7F\n" +
      "     40 28 94 9E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  224-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     E7 31 C7 F1  4F 2B 85 64  99 2F 49 7B  EF C1 46 B5\n" +
      "     C0 0C 0F 64  F9 88 29 8F  CE F0 FD 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  256-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     C0 4F F5 A3  0E E1 0A 53  EF 44 1C 39  82 D5 E2 F6\n" +
      "     C7 A0 22 E2  D4 23 9E 6B  B2 45 55 D0  3F 52 2A A3\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  384-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     A5 50 F3 07  1A 88 26 04  4F F5 F1 4E  88 AA 86 93\n" +
      "     80 87 A1 0C  15 51 02 C0  9D 3B 3E 3B  BF 5C 96 B0\n" +
      "     FE 9C 1C 70  5E 5D 0B AC  CD C9 8F ED  10 25 42 E5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  512-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     57 E3 DE 8C  A3 8A 69 C9  40 5A BF 2A  40 63 B4 85\n" +
      "     5C 77 5B 6D  6C 46 47 25  D3 25 FA F2  7E B6 F1 5F\n" +
      "     08 6B 11 DA  99 E2 52 AC  FC F3 BB E6  2E 08 BC 10\n" +
      "     25 28 50 C4  0B B4 76 6C  32 C1 0D 99  8D B2 7B 10\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     1F 3E 02 C4  6F B8 0A 3F  CD 2D FB BC  7C 17 38 00\n" +
      "     B4 0C 60 C2  35 4A F5 51  18 9E BF 43  3C 3D 85 F9\n" +
      "     FF 18 03 E6  D9 20 49 31  79 ED 7A E7  FC E6 9C 35\n" +
      "     81 A5 A2 F8  2D 3E 0C 7A  29 55 74 D0  CD 7D 21 7C\n" +
      "     48 4D 2F 63  13 D5 9A 77  18 EA D0 7D  07 29 C2 48\n" +
      "     51 D7 E7 D2  49 1B 90 2D  48 91 94 E6  B7 D3 69 DB\n" +
      "     0A B7 AA 10  6F 0E E0 A3  9A 42 EF C5  4F 18 D9 37\n" +
      "     76 08 09 85  F9 07 57 4F  99 5E C6 A3  71 53 A5 78\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  264-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     C3 4E E6 6B  A6 42 63 EE  40 49 4B 52  1E C6 77 AD\n" +
      "     B6 15 B2 86  58 B5 A4 4E  F3 F2 24 EF  BC 12 C6 53\n" +
      "     CB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  520-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     A9 97 7C 91  3A F6 B4 F9  32 F7 0C A2  42 E7 12 AA\n" +
      "     A1 23 93 A8  EB 2B EC C5  59 FC 0F 24  75 95 CC 9B\n" +
      "     52 6C 33 89  D3 5B CC DE  8D 62 BD B2  28 52 56 D9\n" +
      "     D8 5E 39 D9  B0 45 33 A6  44 16 CF 62  5F 00 58 24\n" +
      "     6A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1032-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     32 67 F5 B1  0B 8C 9E 76  9E 1A BF F5  C6 19 0C 14\n" +
      "     02 FD 7A 1C  96 55 79 0D  CA 63 9D 58  FE 31 B4 E8\n" +
      "     73 ED D2 77  7F 1E 79 49  29 C8 B6 DE  EF CF 66 6C\n" +
      "     6A 51 C0 2A  58 04 65 A4  24 32 6A AF  21 C4 14 3F\n" +
      "     BE FA CA 4D  E4 AB 7F FC  15 66 7D D9  5D 65 3C 34\n" +
      "     DC 95 7C 45  1A 70 D6 19  CD C4 F1 10  50 25 9C 9D\n" +
      "     FC E7 5D 34  7E D4 53 B8  DF E4 33 02  EE 35 E5 47\n" +
      "     BA 20 CE 72  CC 36 49 D7  F2 8B E6 97  3A 57 30 E1\n" +
      "     6D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 2056-bit hash, msgLen =  1024 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "Result:\n" +
      "     67 FD 23 E5  BF F8 4D 51  D8 EF 38 9C  83 39 48 CC\n" +
      "     F0 6A 65 8C  4D 7B 4E 5F  74 90 57 3C  3B D1 6D 08\n" +
      "     F1 9B 7B CF  4A 78 2A F8  79 64 AE F0  51 C3 10 44\n" +
      "     59 00 33 BF  24 86 9A BF  78 AB 71 03  8D 9A E7 BE\n" +
      "     88 60 47 8E  44 E1 0D 27  9B 99 96 02  53 40 DF 9D\n" +
      "     22 EB D1 BA  D0 A2 96 B2  A1 20 C5 79  C0 85 71 B8\n" +
      "     B9 60 38 B5  49 BE 94 31  A0 ED 64 03  8B D6 41 F9\n" +
      "     02 E3 F8 2E  AD BC 3F D1  28 16 9C 1A  18 5D F0 0E\n" +
      "     23 97 7D C6  8E 3C CD D1  1E 81 EF 06  56 BF 54 75\n" +
      "     4C 88 8D 4F  AA 57 BB 9C  2F 41 EE 5D  6F 6D F2 7B\n" +
      "     B2 B2 C2 9C  4A 4F 02 6C  DD 18 33 48  53 D6 34 62\n" +
      "     05 96 7B 1C  EA C2 FC F6  75 9B 1E 6E  76 D9 6E 22\n" +
      "     E3 47 32 1E  A7 AB 38 0F  81 83 EB 24  32 76 23 79\n" +
      "     5C 9A 26 19  58 04 16 BC  24 2E ED A5  B5 BA 65 CB\n" +
      "     2F DB F6 D3  4D 74 56 FC  C8 0B 2A C0  AA B8 EE 80\n" +
      "     73 61 C3 30  C1 C3 0B 77  9B 05 94 9A  53 94 E1 27\n" +
      "     B9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1025 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F\n" +
      "Result:\n" +
      "     BD 3B 39 4C  96 59 F1 32  79 0E BA 95  3E 55 1A E7\n" +
      "     DB D9 B3 8F  82 4A D8 8C  BB 45 6A 9E  50 8D 8B 46\n" +
      "     7B 36 BC 52  40 4F 1C 7C  19 87 A7 D8  24 3C 80 AC\n" +
      "     A4 68 E0 97  09 57 6B 9D  3B D3 31 CA  86 74 6B 41\n" +
      "     EC B9 D6 C6  41 C7 15 D7  F9 76 08 89  EF 10 83 B9\n" +
      "     70 B0 45 8E  99 5A 8E 82  90 6A D0 83  11 A5 35 36\n" +
      "     92 78 CF 89  B0 34 8C 01  27 6B 61 FD  65 24 E7 B1\n" +
      "     93 5B 9B 07  84 8D 69 12  11 EA FF 85  76 F7 DC 21\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2047 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     2B 79 07 EE  D9 65 94 EF  7F 9F 6E D3  99 7D 9B DA\n" +
      "     93 E9 68 DE  D3 07 11 08  8C 06 AD A2  69 19 75 DC\n" +
      "     64 0C FC D4  88 4B 95 92  FA 34 AF 73  25 22 66 36\n" +
      "     4B F3 A9 5B  C5 21 3E EA  6A 4D 5C 57  C7 D8 6B 91\n" +
      "     9B EA 5F 82  EF F8 6A 73  9A 44 89 5B  6B 1A BA BF\n" +
      "     8A 3B 0A 96  94 26 1F CF  E9 55 EA 1F  9C 90 40 38\n" +
      "     E4 69 1A FF  2E 2B D0 8D  CB 86 C9 FC  BB FC 46 61\n" +
      "     BA BB A9 D6  35 27 08 EE  82 E8 95 6F  5F 69 B6 AA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2048 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "Result:\n" +
      "     84 2A 53 C9  9C 12 B0 CF  80 CF 69 49  1B E5 E2 F7\n" +
      "     51 5D E8 73  3B 6E A9 42  2D FD 67 66  65 B5 FA 42\n" +
      "     FF B3 A9 C4  8C 21 77 77  95 08 48 CE  CD B4 8F 64\n" +
      "     0F 81 FB 92  BE F6 F8 8F  7A 85 C1 F7  CD 14 46 C9\n" +
      "     16 1C 0A FE  8F 25 AE 44  4F 40 D3 68  00 81 C3 5A\n" +
      "     A4 3F 64 0F  D5 FA 3C 3C  03 0B CC 06  AB AC 01 D0\n" +
      "     98 BC C9 84  EB D8 32 27  12 92 1E 00  B1 BA 07 D6\n" +
      "     D0 1F 26 90  70 50 25 5E  F2 C8 E2 4F  71 6C 52 A5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2049 bits, data = 'incrementing'\n" +
      "\n" +
      "Message data:\n" +
      "     FF FE FD FC  FB FA F9 F8  F7 F6 F5 F4  F3 F2 F1 F0\n" +
      "     EF EE ED EC  EB EA E9 E8  E7 E6 E5 E4  E3 E2 E1 E0\n" +
      "     DF DE DD DC  DB DA D9 D8  D7 D6 D5 D4  D3 D2 D1 D0\n" +
      "     CF CE CD CC  CB CA C9 C8  C7 C6 C5 C4  C3 C2 C1 C0\n" +
      "     BF BE BD BC  BB BA B9 B8  B7 B6 B5 B4  B3 B2 B1 B0\n" +
      "     AF AE AD AC  AB AA A9 A8  A7 A6 A5 A4  A3 A2 A1 A0\n" +
      "     9F 9E 9D 9C  9B 9A 99 98  97 96 95 94  93 92 91 90\n" +
      "     8F 8E 8D 8C  8B 8A 89 88  87 86 85 84  83 82 81 80\n" +
      "     7F 7E 7D 7C  7B 7A 79 78  77 76 75 74  73 72 71 70\n" +
      "     6F 6E 6D 6C  6B 6A 69 68  67 66 65 64  63 62 61 60\n" +
      "     5F 5E 5D 5C  5B 5A 59 58  57 56 55 54  53 52 51 50\n" +
      "     4F 4E 4D 4C  4B 4A 49 48  47 46 45 44  43 42 41 40\n" +
      "     3F 3E 3D 3C  3B 3A 39 38  37 36 35 34  33 32 31 30\n" +
      "     2F 2E 2D 2C  2B 2A 29 28  27 26 25 24  23 22 21 20\n" +
      "     1F 1E 1D 1C  1B 1A 19 18  17 16 15 14  13 12 11 10\n" +
      "     0F 0E 0D 0C  0B 0A 09 08  07 06 05 04  03 02 01 00\n" +
      "     FF\n" +
      "Result:\n" +
      "     83 0E F4 BB  23 DD 6B 0B  38 E1 6D 5D  E2 61 B4 87\n" +
      "     36 6B CC C3  46 23 A1 5A  14 7F 42 FF  4A B8 CD 27\n" +
      "     F9 D2 5A DA  5A F7 99 16  64 01 2A 87  FF 66 7A 1F\n" +
      "     1A 4C 06 4F  8E 33 57 A8  FD F4 6A C2  A2 DC 0D C9\n" +
      "     CE 29 EF AF  D8 F4 5C EF  6B CB FE 76  EE D7 C6 96\n" +
      "     4B BA E8 04  D4 AD 3F 61  CF C2 2B B4  24 08 29 8D\n" +
      "     51 16 01 C0  4C 8B C0 72  CB 59 52 F3  75 A7 4A 1D\n" +
      "     90 CD 4E E3  EE 6F 43 2A  6B F7 BD C4  4C C0 FC 78\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     0 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     C8 87 70 87  DA 56 E0 72  87 0D AA 84  3F 17 6E 94\n" +
      "     53 11 59 29  09 4C 3A 40  C4 63 A1 96  C2 9B F7 BA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     1 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     C4 51 43 CC  B1 24 11 FE  AE 63 17 20  3D 67 D9 E0\n" +
      "     77 69 B8 F7  20 C8 AE F6  17 A6 9E 69  D1 67 9E 53\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     2 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     85 91 BE 2B  7A C2 89 42  E5 B8 D6 92  4D 4A 09 97\n" +
      "     D6 8E 34 30  12 98 E6 7D  F5 EE AB 6B  CF E0 0D 96\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     3 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     26 9B 99 A8  EC F4 BF FA  1C 05 24 4E  2B 8F 9A 5E\n" +
      "     74 5B 8D 47  A9 B5 A5 17  77 9F D8 29  7A 3F 8C 44\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     4 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     62 E6 E2 0A  A6 AB 34 3F  99 73 F0 61  10 45 BD C1\n" +
      "     E6 D1 CB AA  27 4A 7B A1  46 23 41 F4  95 33 B3 16\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     5 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     57 15 1F 10  D3 D4 96 9F  2D 3E 2C 93  E9 D7 EB 8E\n" +
      "     85 26 53 E7  D8 8B 60 10  4B 18 3C 7B  4E 5D 65 BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     6 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     E2 8D 49 6C  0C B9 8D 58  CF 99 96 79  13 AA 23 1F\n" +
      "     68 4D 7B 9F  4E 89 D6 B4  47 1D DF B0  5E B1 B5 3D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     7 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     91 28 A7 A5  91 88 B7 8F  FD 0A 84 B0  B6 33 5B 57\n" +
      "     D0 96 35 1E  36 FD BC C2  05 04 CC C0  C2 B8 F6 46\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     8 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     08 8E B2 3C  C2 BC CF B8  17 1A A6 4E  96 6D 4A F9\n" +
      "     37 32 51 67  DF CD 17 07  00 FF D2 1F  8A 4C BD AC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =     9 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     F8 83 B9 C6  1E 70 2E 35  47 E1 E7 15  50 ED A8 D5\n" +
      "     94 E6 32 27  7C 83 ED 82  D4 CD 0E 3D  AD B9 61 EB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    10 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     98 E3 EE 4F  7D 44 C0 C2  08 BB 16 FC  20 02 6C D9\n" +
      "     9F 86 50 5F  01 86 26 45  6A 81 75 37  3C 37 2A F6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    32 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26\n" +
      "Result:\n" +
      "     2E 8B 4A 36  13 EE 4E B5  42 30 E1 4C  C0 D8 40 56\n" +
      "     C7 C2 E3 D9  1A E2 F9 43  5E 78 FB 3E  93 33 6B EC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =    64 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1\n" +
      "Result:\n" +
      "     B1 DD 13 CF  62 9C 2D 7B  EF 08 E7 BD  09 75 36 6D\n" +
      "     D7 66 89 4E  A3 4C 79 3F  9C D4 20 01  0D 25 86 4C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   128 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "Result:\n" +
      "     E0 EE A1 CB  ED C2 6A A6  F6 B0 6A A6  BE 83 9C E4\n" +
      "     B2 C7 25 CC  B5 BC 0D 71  62 BB 1D 44  2E 58 25 03\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   192 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B\n" +
      "Result:\n" +
      "     9D 0B D9 75  A8 4E E3 65  CC A8 F2 E8  1A 82 90 C3\n" +
      "     EC E8 D5 AC  BA B8 CC 4D  D3 BB 74 C4  03 A3 9C 8F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   255 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     36 3A C0 21  AC A3 DD BB  9C 59 2C D7  ED 42 89 03\n" +
      "     6B 9A 49 AF  82 E2 1C 06  7A 57 9D F9  E2 86 3A 26\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   256 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     5C 30 02 FF  57 A6 27 08  9E A2 F9 7A  50 00 D5 67\n" +
      "     84 16 38 90  19 E8 0E 45  A3 BB CA B1  18 31 5D 26\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   257 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78\n" +
      "Result:\n" +
      "     F8 63 9D 50  E0 09 1D 6B  AD A6 7C 93  5A 2E A7 AD\n" +
      "     8D 26 A5 0E  F6 23 D7 77  74 98 94 6E  AC C4 E3 AB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   384 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "Result:\n" +
      "     64 0C 89 4A  4B BA 65 74  C8 3E 92 0D  DF 7D D2 98\n" +
      "     2F C6 34 88  1B BB CB 9D  77 4E AE 0A  28 5E 89 CE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   511 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     9F 21 6A 60  26 A3 63 E8  77 22 C0 D6  BD 65 71 3F\n" +
      "     BF 6B 88 D3  03 F4 6F C3  B4 6D 15 E8  3B 7B 4B A5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   512 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     34 BE 00 12  71 31 4E E5  9A 9D 66 F4  9B A8 01 AC\n" +
      "     8D 08 2F 57  AF 1C 09 12  69 29 2C F1  F5 B6 9A 87\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   513 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7\n" +
      "Result:\n" +
      "     58 55 DB C0  6B 9D 71 A2  B9 DF 7B C3  46 EE DC 53\n" +
      "     A1 8E BF 46  6D D3 FC 76  6F B5 EB 07  23 E5 FA 18\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =   768 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "Result:\n" +
      "     91 B9 D7 0C  97 63 FF 6D  36 49 EB 56  C8 7E 3A 2B\n" +
      "     E8 05 DF 19  CA 66 59 78  2C 12 73 CE  44 79 89 57\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1023 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     A1 FF 69 F4  D0 6B 82 E7  11 9C 4C 3D  89 93 63 91\n" +
      "     94 10 C8 52  00 F8 07 D0  76 B0 BD 34  0F B1 3B A1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   160-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     0C D4 91 B7  71 57 04 C3  A1 5A 45 A1  CA 8D 93 F8\n" +
      "     F6 46 D3 A1\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   224-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     AF D1 E2 D0  F5 B6 CD 4E  1F 8B 39 35  FA 24 97 D2\n" +
      "     7E E9 7E 72  06 0A DA C0  99 54 34 87\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     4D E6 FE 2B  FD AA 37 17  A4 26 10 30  EF 0E 04 4C\n" +
      "     ED 92 25 D0  66 35 46 10  84 2A 24 A3  EA FD 1D CF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   384-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     95 46 20 FB  31 E8 B7 82  A2 79 4C 65  42 82 70 26\n" +
      "     FE 06 9D 71  5D F0 42 61  62 9F CB E8  1D 7D 52 9B\n" +
      "     95 BA 02 1F  A4 23 9F B0  0A FA A7 5F  5F D8 E7 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   512-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     51 34 7E 27  C7 EA BB A5  14 95 9F 89  9A 67 15 EF\n" +
      "     6A D5 CF 01  C2 31 70 59  0E 6A 8A F3  99 47 0B F9\n" +
      "     0E A7 40 99  60 A7 08 C1  DB AA 90 E8  63 89 DF 25\n" +
      "     4A BC 76 36  39 BB 8C DF  7F B6 63 B2  9D 95 57 C3\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1024-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     6C 9B 6F AC  BA F1 16 B5  38 AA 65 5E  0B E0 16 80\n" +
      "     84 AA 9F 1B  E4 45 F7 E0  67 14 58 5E  59 99 A6 C9\n" +
      "     84 FF FA 9D  41 A3 16 02  86 92 D4 AA  D1 8F 57 3F\n" +
      "     BF 27 CF 78  E8 4D E2 6D  A1 92 83 82  B0 23 98 7D\n" +
      "     CF E0 02 B6  20 1E A3 37  13 C5 4A 8A  5D 9E B3 46\n" +
      "     F0 36 5E 04  33 0D 2F AA  F7 BC 8A BA  92 A5 D7 FB\n" +
      "     63 45 C6 FB  26 75 0B CE  65 AB 20 45  C2 33 62 76\n" +
      "     79 AC 6E 9A  CB 33 60 2E  26 FE 35 26  06 3E CC 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   264-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     FD DA 04 6C  4B DB 38 5A  E6 C7 BB 40  C6 0F 05 13\n" +
      "     00 B4 92 D3  9B 16 05 40  8D 61 F5 E0  4E 0B 9D 2E\n" +
      "     18\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   520-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     C8 2F A6 90  11 48 34 5E  F4 CD 3F 29  8D F4 EB 01\n" +
      "     B9 D6 99 DE  05 22 4B 94  14 C4 BB 95  B2 45 F4 CC\n" +
      "     8A AF AD 33  31 DB 49 2C  B8 26 86 D5  80 BC 2E A0\n" +
      "     3C 2A C5 B5  CF B2 92 68  C5 0E FB EF  5C FF CE F3\n" +
      "     55\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  1032-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     D1 68 2F 5E  9D 54 DE 50  5B D8 AC 68  A5 76 C9 E7\n" +
      "     FB E0 91 05  4F 6B B7 14  F0 9B 2C 5D  EC 08 8D 90\n" +
      "     A4 D0 17 B7  6C 2A 82 F5  3D B7 41 CA  51 F5 D1 DA\n" +
      "     22 98 33 1B  26 F3 8B 9D  93 F8 53 6B  93 C3 A9 27\n" +
      "     56 B3 AD 45  53 22 18 07  38 10 71 EE  DE 0E EF 82\n" +
      "     D9 49 A2 EB  C7 C1 07 78  08 35 8E 25  E9 47 30 92\n" +
      "     1E 2A 88 BC  3E 0F 88 44  8E 16 A9 A1  2D 29 E2 9F\n" +
      "     F6 E4 62 6F  A9 9E 45 F9  A3 DB 99 0C  50 37 5E CD\n" +
      "     04\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:  2056-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     AE F6 DD 3B  35 1A 3D CA  5B 43 81 34  59 F0 A7 C4\n" +
      "     1A 24 3C 3B  3B 60 8F C6  49 A5 21 45  59 28 87 46\n" +
      "     A2 C9 54 8C  2D F3 1E 47  D2 C5 2B E8  CF 97 1C C5\n" +
      "     A9 47 9E CE  F3 88 B2 62  3C D2 92 FA  77 E5 AE B5\n" +
      "     9B AF B8 82  29 36 9D 98  06 A0 A0 B1  DB 43 FE F7\n" +
      "     D4 1F 96 7E  80 B0 CC E8  67 34 04 26  07 FD 75 C7\n" +
      "     74 33 67 C9  8E DA 13 A6  A5 5C 6A 89  1F 86 9E 83\n" +
      "     E7 3B 9D B4  13 FC CF C8  6F 79 04 CC  D9 CC 39 84\n" +
      "     EB 35 65 2E  E6 28 0F D0  CD 71 EC 3E  97 B5 7C 42\n" +
      "     55 B6 28 E6  4D 14 77 F1  E0 7B 76 CF  FC D1 B1 D1\n" +
      "     87 D3 1E 32  B1 C2 ED 0C  1F 15 A1 71  84 62 CF D3\n" +
      "     C5 23 98 54  09 4C 90 BC  2A 7E 8F 84  94 8B BC BD\n" +
      "     03 B7 31 D9  A7 F4 CE CE  CA BC 11 9A  10 1F 6F 59\n" +
      "     E4 B5 B7 B2  93 18 D8 48  7C 33 D5 10  57 ED 82 D6\n" +
      "     D7 EA 31 14  F3 A4 3E 90  F0 06 0A 2D  D9 D2 D5 F3\n" +
      "     FE 5C 4B 53  6F 7D 17 2C  DF 0C 31 87  46 C4 99 79\n" +
      "     8D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  1025 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1\n" +
      "Result:\n" +
      "     97 B8 20 38  2F 83 2B 38  3A C3 FE 28  75 A4 9C 8F\n" +
      "     41 78 42 43  A6 CF BF EC  BC 12 76 60  5A E1 A8 69\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2047 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     0F DC 97 80  11 7A 68 3B  2E C6 43 B8  66 49 9C 3B\n" +
      "     09 A5 4D 29  2A 39 AC AD  32 4A 59 E0  B1 38 05 6D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2048 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     96 4A 3E E1  BD E5 9B 10  84 E6 4C 12  15 1D 92 DC\n" +
      "     F2 1B 7A 06  AA 3B 37 A5  02 99 CA 8D  76 04 CE 12\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-256:   256-bit hash, msgLen =  2049 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "     4E\n" +
      "Result:\n" +
      "     FE 9C 9C D1  67 11 AE 5F  F0 5C E1 20  3F 7E 64 AF\n" +
      "     DF C5 63 73  C2 1F BE E2  D6 FB 1A 37  E8 26 1E 8B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     0 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     BC 5B 4C 50  92 55 19 C2  90 CC 63 42  77 AE 3D 62\n" +
      "     57 21 23 95  CB A7 33 BB  AD 37 A4 AF  0F A0 6A F4\n" +
      "     1F CA 79 03  D0 65 64 FE  A7 A2 D3 73  0D BD B8 0C\n" +
      "     1F 85 56 2D  FC C0 70 33  4E A4 D1 D9  E7 2C BA 7A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     1 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     54 EA EA 3E  D9 F3 34 01  BA 8A F6 45  B3 D3 80 FC\n" +
      "     40 2E 61 B4  3B 84 ED 26  B3 D1 E9 80  72 A4 B0 29\n" +
      "     CA D8 6E DB  DC 17 34 3B  AD A6 27 0D  9E EB B0 44\n" +
      "     17 25 AF EA  51 AD 74 F0  43 CD 25 4B  BC CE 2C B7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     2 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     B0 55 F4 35  FF 61 15 13  2E F7 71 BF  F1 E3 82 04\n" +
      "     3D 93 BE 94  AD 3E 2E 17  15 E6 15 86  32 2C 5E 25\n" +
      "     99 C8 8B 1E  48 3C 22 2D  EB 44 86 68  C4 1C BD 48\n" +
      "     DE 27 03 93  1C 98 6D 3F  C0 D6 8F B9  00 87 E3 40\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     3 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     FC AB D6 46  33 C0 1B 1F  51 80 32 1C  3A 73 4D 37\n" +
      "     58 CB D7 35  FC 4A 77 F4  32 E2 D0 C9  9E 5A F2 8D\n" +
      "     AF 26 9D CC  B3 4A 74 35  E9 31 15 7E  49 B8 D2 E3\n" +
      "     EE D0 FC FA  B7 1F 16 33  D8 89 E6 54  28 D9 52 42\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     4 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     15 6E 61 BF  4C 11 04 6E  64 3B 86 86  C4 BD 85 B6\n" +
      "     C7 85 DD A5  B4 66 94 3D  DF D6 1E 4C  AC 05 EC CC\n" +
      "     B9 B8 2B 27  77 69 29 F4  A3 39 AD 7F  9A 39 91 AF\n" +
      "     E3 E4 9A 3A  40 7E 0E 7A  75 E5 92 87  DE F2 F8 99\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     5 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     18 5C 59 DC  2F 1B 49 D3  92 04 20 41  CC F8 C3 B2\n" +
      "     01 69 22 59  70 4A 90 F7  50 DA 33 DA  E8 E6 01 61\n" +
      "     9A 5E 7B CB  2A 72 31 97  D2 48 E8 05  AB 0F 20 9A\n" +
      "     34 01 FB 6F  B6 71 34 EE  3A 0F EC 77  F0 6F 41 6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     6 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     8F 6B AD 82  4D 6B 89 F9  FE DA 70 1B  6B 7C 7D CB\n" +
      "     BB 0E 48 9E  C3 2F F9 84  CB C7 60 AE  09 58 2E A1\n" +
      "     C5 FC 06 2B  BF DC B7 6D  E5 D2 0C 8A  28 BF E5 38\n" +
      "     5C 36 EC 6A  41 A5 E9 99  58 07 55 82  E4 24 CF 53\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     7 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     CD 21 76 A5  FE 82 3E D6  EF CB 6F 15  8F F3 5C 01\n" +
      "     0F 86 4C C8  A9 14 6C CD  F6 F1 90 41  4D D0 6B 82\n" +
      "     51 54 0F 94  EF F5 80 A5  66 4D AE 3D  F1 62 8F 84\n" +
      "     01 B1 F2 DD  4B B5 FC 78  E9 FE 7E ED  FA AC 35 9A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     8 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     C4 9E 03 D5  0B 4B 2C C4  6B D3 B7 EF  70 14 C8 A4\n" +
      "     5B 01 63 99  FD 17 14 46  7B 75 96 C8  6D E9 82 40\n" +
      "     E3 5B F7 F9  77 2B 7D 65  46 5C D4 CF  FA B1 4E 6B\n" +
      "     C1 54 C5 4F  C6 7B 8B C3  40 AB F0 8E  FF 57 2B 9E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =     9 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     BF 89 C0 6D  49 57 EE 1B  EE FB C5 1A  CA 0A 49 A8\n" +
      "     8B 7C 0F 8E  FC B5 B8 8C  79 F5 E0 B9  18 3C CD F8\n" +
      "     73 8B FE C1  CA B9 5A D2  EF 1E 6D 35  C2 54 CB 09\n" +
      "     6E 00 A0 FD  94 FD B4 4F  62 F5 F8 FC  22 64 15 8D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    10 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     B8 3B D8 9A  8D 79 26 71  BB 65 3B D5  4D 20 02 E0\n" +
      "     31 6E F1 B9  D1 15 4C 24  CD E6 1A D3  3E 68 20 40\n" +
      "     2E C5 A1 46  2A CA B2 AD  4F 4B 53 85  32 2F 5B E0\n" +
      "     E5 9B D8 CD  E5 86 96 12  94 CC 2E B3  7F 0D 3D 03\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    32 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26\n" +
      "Result:\n" +
      "     92 B7 29 41  95 70 B2 2B  B7 5B 50 CF  72 DB 16 8B\n" +
      "     4C 73 56 94  BC 8A D4 43  3C 7C 18 7B  0B DD 48 9C\n" +
      "     C3 F6 7A E2  3E 50 18 EB  F4 10 0C F6  AF B2 E1 DB\n" +
      "     1F 17 5D C2  66 D9 25 75  E8 D8 26 1D  6E 6E 27 6E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =    64 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1\n" +
      "Result:\n" +
      "     B6 40 71 E6  8C B2 40 FB  CC EA 60 39  F3 51 D8 0E\n" +
      "     9A B3 31 4B  16 B5 88 8E  C4 EE 82 93  32 37 4B 1A\n" +
      "     57 AE DD E7  76 0B 39 09  9C 6D AD CC  1F 39 33 B9\n" +
      "     AF 75 58 2F  62 3E B7 BD  CF FA 33 B2  58 74 44 7C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   128 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "Result:\n" +
      "     03 04 F6 E4  F2 EF 71 C9  53 9E 95 EB  CE 42 A1 6B\n" +
      "     45 1A D8 B5  2A 34 C2 B6  9E 53 69 78  F1 64 B7 C2\n" +
      "     1F D5 2D 15  E3 82 5E 09  83 5A 41 AE  51 B7 F0 16\n" +
      "     84 96 93 61  B7 50 62 74  C7 28 65 B8  A5 AE 3C EE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   192 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B\n" +
      "Result:\n" +
      "     B4 29 70 F4  C4 58 28 5D  36 A6 7D 9D  9B 3D 8F 13\n" +
      "     D2 F4 7F E5  E4 8A 03 74  B8 97 F4 7D  8A E0 D5 3B\n" +
      "     72 CA 9C 32  1D F7 C1 FD  B8 F7 55 1B  DE 4D 3A C6\n" +
      "     27 5F E0 2B  E4 68 45 4B  E4 2E FB F7  C4 3B 80 AE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   255 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     D3 1E 6D 14  FE CB 57 16  BB 27 D3 DC  54 9B 59 C5\n" +
      "     B6 09 63 A5  F1 6E EC 7F  73 7C 20 3A  B7 ED E3 E2\n" +
      "     12 F9 32 54  9B 89 27 C0  5A AA 1F 3B  17 60 0D A2\n" +
      "     F3 02 3A 38  59 C7 A7 73  16 48 2C 0D  F8 71 94 4E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   256 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     AB EF B1 79  D5 2F 68 F8  69 41 AC BB  E0 14 CC 67\n" +
      "     EC 66 AD 78  B7 BA 95 08  EB 14 00 EE  2C BD B0 6F\n" +
      "     9F E7 C2 A2  60 A0 27 2D  0D 80 E8 EF  5E 87 37 C0\n" +
      "     C6 A5 F1 C0  2C EB 00 FB  27 46 F6 64  B8 5F CE F5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   257 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78\n" +
      "Result:\n" +
      "     B7 84 82 9E  16 52 C8 5C  94 60 22 71  27 27 62 07\n" +
      "     BE D0 92 AE  F6 BF B5 13  69 E4 CD 41  F7 DE 61 1B\n" +
      "     9B DF 14 61  3E AA E6 FA  1C 16 D6 2A  5D 41 3F 40\n" +
      "     B8 06 08 04  3E 0C 39 5F  CC 05 3E D4  C0 10 62 3D\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   384 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "Result:\n" +
      "     5C 5B 79 56  F9 D9 73 C0  98 9A A4 0A  71 AA 9C 48\n" +
      "     A6 5A F2 75  75 90 E9 A7  58 34 3C 7E  23 EA 2D F4\n" +
      "     05 7C E0 B4  9F 95 14 98  7F EF F9 7F  64 8E 1D D0\n" +
      "     65 92 6E 2C  37 1A 02 11  CA 97 7C 21  3F 14 14 9F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   511 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     AC BE 18 5E  BF 39 26 66  2C 4C 1F C9  84 3B 5B 28\n" +
      "     F9 BA FA 91  57 04 31 0E  EF 92 D7 AC  54 53 F1 05\n" +
      "     D3 C1 ED EA  C8 54 01 54  BD B4 7D 40  5F EC 02 A3\n" +
      "     34 E6 50 72  C6 36 11 20  71 F3 41 02  46 7F E1 E8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   512 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     02 D0 15 35  C2 DF 28 0F  DE 92 14 6D  F0 54 B0 60\n" +
      "     92 73 C7 30  56 C9 3B 94  B8 2F 5E 7D  CC 5B E6 97\n" +
      "     99 78 C4 BE  24 33 1C AA  85 D8 92 D2  E7 10 C6 C9\n" +
      "     B4 90 4C D0  56 A5 35 47  B8 66 BE E0  97 C0 FB 17\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   513 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7\n" +
      "Result:\n" +
      "     67 5B 04 15  63 C9 B1 29  3E 35 ED 53  4E 9F 86 E0\n" +
      "     BB C3 7A 73  C1 B3 79 94  A9 41 30 93  E4 70 07 14\n" +
      "     A9 E6 9E 6A  9F CB ED 7D  3A 21 3A C2  68 71 7B 41\n" +
      "     9B 37 94 57  27 B1 14 07  5F 2F 87 22  6A 53 90 FB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =   768 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "Result:\n" +
      "     E3 0E 94 6D  43 98 D1 02  C2 FD E5 6E  F7 61 1D D1\n" +
      "     33 D2 D3 06  6B A3 20 F2  0A 00 E8 A8  02 19 F5 4D\n" +
      "     09 9F FD 5A  EB E1 C9 4E  78 8B BC 8A  DA C3 BA 3E\n" +
      "     37 4E 0C EB  55 4C 4F A9  D4 C8 7A 79  B2 C6 49 AF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1023 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     AF F9 C8 3D  03 72 41 CD  68 54 E7 F1  58 EB 2E 8F\n" +
      "     89 B8 8C FB  71 6F D6 1F  F0 04 19 93  6B 82 22 14\n" +
      "     0C 4F 30 89  BD 50 5B CE  46 B9 25 94  95 CB B1 A5\n" +
      "     AC 6E 0B EF  51 30 1C 3B  E0 68 83 D2  C0 C5 5C ED\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   160-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     EF 03 07 9D  61 B5 7C 60  47 E1 5F A2  B3 5B 46 FA\n" +
      "     24 27 95 39\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   224-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     D9 E3 21 9B  21 4E 15 24  6A 20 38 F7  6A 57 3E 01\n" +
      "     8E F6 9B 38  5B 3B D0 57  6B 55 82 31\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   256-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     80 9D D3 F7  63 A1 1A F9  09 12 BB B9  2B C0 D9 43\n" +
      "     61 CB AD AB  10 14 29 92  00 0C 88 B4  CE B8 86 48\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   384-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     82 5F 5C BD  5D A8 80 7A  7B 4D 3E 7B  D9 CD 08 9C\n" +
      "     A3 A2 56 BC  C0 64 CD 73  A9 35 5B F3  AE 67 F2 BF\n" +
      "     93 AC 70 74  B3 B1 99 07  A0 66 5B A3  A8 78 B2 62\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     1A 0D 5A BF  44 32 E7 C6  12 D6 58 F8  DC FA 35 B0\n" +
      "     D1 AB 68 B8  D6 BD 4D D1  15 C2 3C C5  7B 5C 5B CD\n" +
      "     DE 9B FF 0E  CE 42 08 59  6E 49 9F 21  1B C0 75 94\n" +
      "     D0 CB 6F 3C  12 B0 E1 10  17 4B 2A 9B  4B 2C B6 A9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1024-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     8C 25 D3 14  11 0D 1C 0D  58 05 4C 96  A1 9D 57 1E\n" +
      "     26 A4 5D 53  62 AA 8F 47  54 7E 53 E0  BE 4A 83 0A\n" +
      "     5F 2C 29 CC  D8 8E 21 85  FE BA D0 24  A4 69 6F 2D\n" +
      "     BE 83 07 DC  15 0E 7A 58  B3 79 3B 1A  93 FA E2 52\n" +
      "     3E 2D 23 9C  59 A2 3A 1C  C1 27 B3 C4  81 A9 80 91\n" +
      "     62 E6 0B 4C  B0 1C 01 1B  96 30 32 2C  8F E9 74 5D\n" +
      "     56 D0 F3 AE  D5 4B 34 90  57 8D B4 69  29 01 EA FC\n" +
      "     19 60 C1 53  59 17 6A 9C  09 90 B3 2B  8C A8 F9 4B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   264-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     90 8D D2 01  AF 09 F3 91  8C 63 76 E9  97 80 85 5E\n" +
      "     BF 08 23 00  8E 6C 35 3F  B9 93 3F 63  34 24 FF 09\n" +
      "     1F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   520-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     F4 D2 49 3A  56 AE 27 E6  63 08 BE 82  26 1B F7 9F\n" +
      "     AE 6E A8 56  CB 1B 21 71  92 0A B3 2E  9C 2A 89 DE\n" +
      "     D1 DD 1B CA  EB B2 A5 CF  31 9A 17 1A  2D 27 44 96\n" +
      "     7B 30 63 A7  B3 C1 9B 0B  61 FB 1E 07  FA 8A 9A F0\n" +
      "     AE\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  1032-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     38 93 B5 0A  4B AB 1C 04  50 02 D4 4D  8C 4E B2 E9\n" +
      "     47 20 8C A5  1A BE 16 0B  FD 8F E7 A0  80 95 BD 6A\n" +
      "     69 21 95 99  EE 83 B5 B8  4D 96 68 CC  BD 40 B3 53\n" +
      "     C9 84 2D 9C  47 0C 03 EF  5A 06 87 36  8A C7 26 FB\n" +
      "     18 7D 92 23  27 25 C8 5A  FF CA 29 C1  EA F0 42 64\n" +
      "     D7 56 9D D1  93 A6 29 99  91 91 AF 7B  4B BE D0 F0\n" +
      "     6E 3B A3 ED  05 33 87 55  A3 83 A2 62  B4 78 19 38\n" +
      "     A2 32 3F 23  05 D8 17 9C  39 A8 CA 64  AA 02 DE D3\n" +
      "     F5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:  2056-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     24 E8 09 F7  66 AC 61 6D  DE 1A 5C 9E  8D C3 3F 25\n" +
      "     23 A5 B7 E7  0C 33 77 32  79 B8 81 22  1E 13 C9 C5\n" +
      "     6E 3F 88 F7  39 74 57 54  6A 1B 41 D4  FE AD A7 E5\n" +
      "     23 1B 3B 4F  64 24 15 D1  52 8B B7 BE  C3 21 3B 77\n" +
      "     D3 E6 CC 00  6A 45 00 A3  38 4B 4C 40  E2 6C EC 4C\n" +
      "     B7 33 4E 03  5D 2B F9 02  60 C9 68 69  D0 B6 C3 9A\n" +
      "     57 74 9E FB  E4 E5 79 17  6C 32 CD C6  C1 D4 06 07\n" +
      "     E3 66 D1 D5  0C 66 91 01  F9 C2 E5 32  A2 E8 04 0D\n" +
      "     48 B6 63 1B  E1 C1 2E 6D  04 E6 DA CB  5B 68 58 6F\n" +
      "     98 A7 17 2E  64 DF 3A EF  ED D3 87 C5  DD 56 FB D2\n" +
      "     63 75 34 9E  5D 55 D9 FA  BC 0E 91 F3  B3 0A 35 70\n" +
      "     C5 C7 97 58  79 DD 28 96  81 CE 13 92  68 F8 A8 A1\n" +
      "     00 81 A0 EB  36 89 5E 8D  D0 B1 41 84  4A 00 4B A1\n" +
      "     12 49 C9 1E  50 5C 9E 84  11 EA 37 6A  8C 41 07 85\n" +
      "     53 59 BA 34  1D C7 FF 1B  1B B2 73 60  07 C1 F9 52\n" +
      "     84 0C DF A5  21 C6 EB F0  F3 F3 53 31  33 F5 0C D1\n" +
      "     AC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  1025 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1\n" +
      "Result:\n" +
      "     1B 4E FF F9  57 C4 FE CD  CA E5 1A 90  3E 95 A8 D5\n" +
      "     D0 C7 DF 2D  60 14 3A 42  76 80 E1 D4  9C 67 1D 4D\n" +
      "     FB 03 8F 36  46 44 48 DE  B3 02 E4 98  34 D8 B2 3B\n" +
      "     44 57 81 42  54 57 72 0E  EC 7B AD 7A  21 17 F2 1C\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2047 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     FA D7 20 CA  33 18 1E AB  15 4F 33 3A  FA 19 20 9B\n" +
      "     28 AB 77 B5  AE 15 FB E5  B0 C6 00 98  7C DE D5 BC\n" +
      "     55 E2 9D 15  8D 41 BE 85  B7 74 11 D3  02 77 F6 16\n" +
      "     F3 EA 8D 18  2B 82 8A EE  5A 94 1A FA  3A 81 55 5E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2048 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     9B 29 A3 0B  D2 13 DF C9  5C 86 78 CF  01 87 5F 68\n" +
      "     CC 2A 22 35  0D 71 61 FB  99 86 15 9E  EC 3D 3C 85\n" +
      "     0C A0 6A 97  6C E6 95 87  1D 40 28 23  A4 E8 2F 1B\n" +
      "     21 D3 59 6B  CA B8 E0 4D  69 C4 5E 9C  7B EF C9 E3\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-512:   512-bit hash, msgLen =  2049 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "     4E\n" +
      "Result:\n" +
      "     68 59 FA E4  48 65 64 3F  75 2F D4 7F  90 BB 53 8A\n" +
      "     90 4F E4 A6  80 68 D3 AD  5F AA 1D F6  0B 9D 7F 3D\n" +
      "     28 E3 3B 5E  AC 6D ED 08  16 00 A0 59  D2 49 8A 91\n" +
      "     F4 0D 11 0B  84 67 CA 55  58 AD E5 CB  DF 93 C6 9A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     0 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "    (none)\n" +
      "Result:\n" +
      "     0F FF 95 63  BB 32 79 28  92 27 AC 77  D3 19 B6 FF\n" +
      "     F8 D7 E9 F0  9D A1 24 7B  72 A0 A2 65  CD 6D 2A 62\n" +
      "     64 5A D5 47  ED 81 93 DB  48 CF F8 47  C0 64 94 A0\n" +
      "     3F 55 66 6D  3B 47 EB 4C  20 45 6C 93  73 C8 62 97\n" +
      "     D6 30 D5 57  8E BD 34 CB  40 99 15 78  F9 F5 2B 18\n" +
      "     00 3E FA 35  D3 DA 65 53  FF 35 DB 91  B8 1A B8 90\n" +
      "     BE C1 B1 89  B7 F5 2C B2  A7 83 EB B7  D8 23 D7 25\n" +
      "     B0 B4 A7 1F  68 24 E8 8F  68 F9 82 EE  FC 6D 19 C6\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     1 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     47 28 53 70  0A 4E B0 C7  28 CC 3A E7  84 A6 AE C9\n" +
      "     CA FE 79 47  D7 E0 25 71  43 8D AF A5  0B D6 48 EC\n" +
      "     FC 4A AD C1  E4 8A EF EF  71 78 33 0F  DE 72 53 94\n" +
      "     C8 EC BC B4  8F 94 BC 4D  9F E6 02 AB  AF 5A 36 B2\n" +
      "     8F 27 2A 58  E0 3E 61 C9  4B F8 9C FE  E2 7A D2 9D\n" +
      "     8D 94 54 EE  7A 91 83 84  54 38 26 47  D0 ED 8D BA\n" +
      "     1B CF 6C 95  97 3E 7C 5B  45 D2 22 82  78 AB 4E 5A\n" +
      "     72 22 A5 C8  E2 41 43 F8  1D D6 EF 30  0D A8 8A BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     2 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     11 42 5D 06  3A B0 3D BE  12 2A 4D B2  33 ED C0 38\n" +
      "     15 38 67 D4  84 1A AB 3E  09 17 B8 1F  C5 80 59 CA\n" +
      "     92 8B D1 5E  0D D1 D0 80  AB D3 33 04  D7 B8 0B F9\n" +
      "     FF 12 CE 39  1D 2D 13 C2  58 FF FC 3B  62 01 1B 47\n" +
      "     F6 82 F4 4B  10 B4 E5 90  92 A9 07 C7  63 D3 A8 66\n" +
      "     99 48 50 C9  E0 DD C2 40  05 99 70 0D  94 2B D4 91\n" +
      "     3F D7 38 E7  1B 55 D7 9A  03 02 76 74  CE FF 3F 1B\n" +
      "     89 9B 66 74  F4 21 C0 B7  EE 43 CF 00  9D F6 DC EA\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     3 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     2C 6B 60 FA  31 1B 79 21  D4 4D DC 99  AB CD 91 AA\n" +
      "     29 93 43 2F  9B 14 92 8C  E6 31 06 B5  FC 37 60 8D\n" +
      "     1B 12 E7 EF  AD 2E 76 93  7C A7 7B B5  AB B8 28 B3\n" +
      "     BC 21 23 FE  AA 49 F8 00  26 F4 E3 6F  88 CD AD 10\n" +
      "     A2 83 AA 28  2E 09 D0 26  24 E9 BD 58  6D 4C C6 A0\n" +
      "     F8 C9 0A 21  83 AF B7 1C  DA A1 5A D0  58 84 5E 20\n" +
      "     7B EB 12 A8  5C 3A 17 3A  61 69 48 FD  99 91 5B 69\n" +
      "     35 C0 76 8B  23 D9 7C 0B  A5 2A F9 85  E0 7B 87 AF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     4 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     FC CA 16 4A  E7 D8 51 AC  E6 F3 99 CB  AB A4 09 FD\n" +
      "     50 4C 43 52  C3 71 E0 7B  3E 19 B3 B2  6C 14 97 DD\n" +
      "     27 FA 78 78  ED 26 4D C3  AA 09 78 91  8A 69 4F 44\n" +
      "     AE 1E 78 8C  B1 27 BF 82  09 72 00 BC  48 1B 47 AD\n" +
      "     02 BD 56 73  6A 6A 5A BE  C2 A4 D8 AD  64 8A 9C BC\n" +
      "     13 AD FD BC  1F 8F D1 51  B8 88 F9 FF  A1 38 7D B6\n" +
      "     48 8B 1E 94  CB 4C D1 69  0D B2 DC 5C  8F 9D 89 99\n" +
      "     C4 22 3F 74  F7 29 AA 36  19 D8 45 AB  0A 37 F9 50\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     5 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     0B B6 A8 33  4D F7 3C 46  09 24 B4 FB  20 40 19 56\n" +
      "     73 A7 F0 86  08 16 A3 2A  93 9A C0 77  24 61 DD 20\n" +
      "     E0 68 A3 A5  29 77 94 13  9A 9D 68 9B  91 22 A1 44\n" +
      "     82 BD EA 22  4C B1 D6 88  95 A0 07 80  BF 55 46 BD\n" +
      "     B6 DF 01 BB  16 CA C2 5F  1B 0B F3 62  E6 B4 5B 01\n" +
      "     F9 E4 E8 97  E4 60 CB 04  49 32 51 79  7B 65 48 FE\n" +
      "     1C 97 48 ED  6C A5 52 62  36 68 A8 2E  0B A5 2C 5E\n" +
      "     9A 99 F7 04  55 BC 12 76  10 86 DC A3  A5 30 59 EB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     6 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     44 4A AD BD  22 7F 00 E1  74 EC 80 14  43 1C FF E6\n" +
      "     3A 08 D0 46  DF C9 62 6E  19 DF 31 EE  56 F7 B8 EC\n" +
      "     5F 2B 95 30  3C 34 D4 FE  B4 06 D8 56  0F 1B B5 14\n" +
      "     5A CB 0A D2  9B EB 0F 6C  D7 97 83 BB  91 B6 27 70\n" +
      "     83 D8 9F 7F  4D 9A 82 EE  03 9F 96 64  7C BF B3 8A\n" +
      "     B0 FC D9 14  47 70 36 07  49 3C 68 FF  1F 4B F2 80\n" +
      "     D5 69 AC B9  C9 D6 22 AB  61 03 95 2C  87 22 AC B6\n" +
      "     F2 D5 08 6C  46 CB 2F FE  19 57 C1 15  37 A7 78 51\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     7 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     BD 1F AE 51  D5 0C 0A 00  B4 72 56 25  95 0D 74 FD\n" +
      "     60 32 3E D9  76 40 D6 65  99 6F 87 61  79 30 04 23\n" +
      "     12 A3 08 65  DB 31 0A 11  11 37 76 FC  52 4C 94 DB\n" +
      "     A4 01 8C BA  7B 9F 02 4D  25 F3 9B 36  BE ED 95 A2\n" +
      "     73 99 85 D0  5E F5 F5 BF  28 F8 B4 7B  BC 50 F6 CB\n" +
      "     D3 EE 4D 7B  CF 1B 83 6B  A6 8F 21 12  E1 A8 CC F5\n" +
      "     F6 41 A7 3B  C4 A8 D4 A2  51 DC DF F8  D6 EC 98 9B\n" +
      "     B9 D9 F8 5E  29 C2 BF 4E  7B 72 5B E2  98 E5 F4 D8\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     8 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB\n" +
      "Result:\n" +
      "     64 26 BD C5  7B 27 71 A6  EF 1B 0D D3  9F 80 96 A9\n" +
      "     A0 75 54 56  57 43 AC 3D  E8 51 D2 82  58 FC FF 22\n" +
      "     99 93 E1 1C  4E 6B EB C8  B6 EC B0 AD  1B 14 02 76\n" +
      "     08 1A A3 90  EC 38 75 96  03 36 11 94  27 82 74 73\n" +
      "     47 70 67 1B  79 F0 76 77  1E 2C FD AA  F5 AD C9 B1\n" +
      "     0C BA E4 3D  8E 6C D2 B1  C1 F5 D6 C8  2D C9 66 18\n" +
      "     00 DD C4 76  F2 58 65 B8  74 82 53 17  31 87 D8 1D\n" +
      "     A9 71 C0 27  D9 1D 32 FB  39 03 01 C2  11 0D 2D B2\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =     9 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     01 CF B1 34  26 1D FD 1F  BB 63 68 06  B7 46 81 49\n" +
      "     11 83 60 2E  DA E2 C9 3F  07 22 9B 4D  EF 4E BB A1\n" +
      "     36 01 5A BE  12 E9 B7 8B  47 13 DE 2B  2A 5B 16 D0\n" +
      "     07 79 13 9E  75 32 9A 06  48 41 07 FF  83 A6 1F 91\n" +
      "     FD 35 34 CB  14 65 99 A7  81 3A 7E DA  94 07 22 B2\n" +
      "     31 B2 CB C5  EB E1 FD 80  C0 15 1F DC  60 83 EA 65\n" +
      "     63 C5 E0 C1  1D 4D 96 87  B2 F3 FF 41  AE 8B B2 38\n" +
      "     72 2C 17 04  8D 08 CA E9  96 6C 1B 50  DD 3B C6 9F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    10 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1\n" +
      "Result:\n" +
      "     44 2F E1 2E  A3 0B 93 C7  F6 0C 8A 4B  78 C4 ED 59\n" +
      "     F9 CB 63 93  4D 6A 20 74  67 DB E8 B7  4B CA FB 61\n" +
      "     B1 0E DE 36  8C 7D 59 C9  49 54 5F F6  39 CC F3 96\n" +
      "     CE 3A D6 BD  51 0B 56 76  00 0C 6F 6C  FC B3 CB 0D\n" +
      "     B7 B2 22 6E  23 75 3B DF  51 D3 51 94  0F CE E0 A8\n" +
      "     76 BB D4 52  80 67 EA 92  20 1D 46 C0  57 5C 7F 70\n" +
      "     C4 85 25 07  42 93 28 0B  7A E8 A4 B4  EB A8 0B ED\n" +
      "     43 53 AE 08  B6 06 3F 34  B7 D2 9E 8C  CE 14 95 72\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    32 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26\n" +
      "Result:\n" +
      "     8E 34 DD D7  07 13 DD E2  44 A6 E3 2B  BA E2 96 6C\n" +
      "     55 7B 64 31  59 E4 79 D1  1A 21 9D 87  36 B6 2E 86\n" +
      "     80 29 92 31  07 48 4A EA  E0 F2 88 14  A2 10 CF CE\n" +
      "     03 CE EF 89  0E 44 8F C5  8F B7 5C D2  76 9A F2 87\n" +
      "     7A 03 86 5D  AD A0 F2 1D  DB 80 2E 42  90 24 50 24\n" +
      "     E3 D6 1F F2  AC FA 08 39  88 82 7A CB  CB 21 91 7E\n" +
      "     D9 6C 0F 20  D6 2B 28 1D  0D B2 E4 7F  CB EB 46 5E\n" +
      "     42 23 12 5F  76 0A DD BF  89 CD C3 46  69 6D 5B 48\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =    64 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1\n" +
      "Result:\n" +
      "     5A FA 09 A9  48 A7 32 FC  BF EA 7C 05  CD 52 46 9B\n" +
      "     5E A3 D7 2C  EF 67 49 82  7F DF A1 BE  85 AE F4 D3\n" +
      "     F0 F9 34 21  8F EA 7D 41  95 A7 6F A9  CF AD E4 10\n" +
      "     75 8B 4E 93  68 07 FD A5  BB CC 76 01  27 C8 BC 38\n" +
      "     4A 07 56 CC  ED 82 34 F4  A2 98 B9 DF  C9 D1 6A 00\n" +
      "     48 CC 17 1F  32 49 52 7D  20 61 AC 93  C5 5D BF 80\n" +
      "     72 6A 79 12  35 16 DE 07  74 4E 79 A2  FD E1 A6 45\n" +
      "     21 B4 17 5F  F6 8B F3 AA  2A CC 43 A7  DD 28 50 94\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   128 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "Result:\n" +
      "     1B 47 DB A3  B9 71 45 18  05 DC 69 D2  A4 0B 3D A9\n" +
      "     42 CE AD 2A  96 37 F7 AF  D4 3F 90 2A  E9 44 66 D1\n" +
      "     CC 82 A4 C7  F3 5D FA F0  0F 32 BA 46  B8 FD 16 BC\n" +
      "     2A 85 24 B0  D7 6B DB E3  2E B1 37 B9  72 1C 78 D1\n" +
      "     32 67 EE F0  CE 7A 9B F9  8A 96 88 84  0C DE C6 7F\n" +
      "     3E 61 58 9B  63 B0 85 29  D4 33 1F E2  2F 50 10 5A\n" +
      "     44 A3 6E D6  54 CA 2E 61  13 C2 ED E4  CC 70 02 A7\n" +
      "     9E B3 1F CD  65 FE 58 56  C7 30 76 12  EE CD DF 6B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   192 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B\n" +
      "Result:\n" +
      "     30 49 95 06  2F EC 83 4F  07 A7 B3 CB  78 AF 73 E2\n" +
      "     7B A0 95 61  1C 01 DE 2E  A8 6D 7E 73  53 18 C2 FA\n" +
      "     B2 4E 64 59  44 7B 19 7C  95 EA 84 3E  8C 97 B7 5E\n" +
      "     B1 31 CB CB  00 54 CA 50  F9 67 69 85  44 D1 A1 35\n" +
      "     46 2B 31 5F  72 79 C1 FA  0B 58 D6 D0  47 8A 48 16\n" +
      "     80 07 B3 9D  7F 90 D8 04  1F 5B E8 2B  02 72 FE C0\n" +
      "     F2 27 2B 61  C4 49 8D 5A  2E B8 4C 16  24 3B E9 6E\n" +
      "     19 84 E9 47  23 E4 76 63  68 C6 58 FD  3B CC 1E 0A\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   255 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     21 0E 05 0B  03 60 93 40  A3 7B 98 A8  D9 70 F1 38\n" +
      "     BC FF 12 05  E5 60 14 FF  C3 79 6C 70  13 A3 42 10\n" +
      "     47 6A 57 AD  E8 AC 28 87  E9 90 66 B3  B4 92 65 EA\n" +
      "     5B 59 EC 5A  BC 75 19 79  33 C9 F4 7B  EA 97 7E FC\n" +
      "     99 4F 9F D4  58 2F FD 4F  80 9A FD 84  68 9C B7 5C\n" +
      "     44 25 C9 CB  77 62 E4 8D  8A 45 C3 92  BD D4 BD 3C\n" +
      "     D8 7E 9A A6  DA 2C 5E B0  7E EC C0 4F  ED 16 09 46\n" +
      "     A1 45 8F E7  CC 43 08 D5  C1 BC DF 75  F6 EC 32 B7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   256 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "Result:\n" +
      "     14 0E 93 72  6A B0 B0 46  7C 0B 8A 83  4A D8 CD A4\n" +
      "     D1 76 9D 27  36 61 90 2B  70 DB 0D CB  5E E6 92 AC\n" +
      "     B3 F8 52 D0  3B 11 F8 57  85 0F 24 28  43 28 11 30\n" +
      "     9C 1D CB E5  72 4F 00 26  7E A3 66 7E  89 FA DB 4E\n" +
      "     49 11 DA 6B  0B A8 A7 ED  DF 87 C1 C6  71 52 EF 0F\n" +
      "     07 B7 FE AD  35 57 31 84  78 BD EF 5A  D1 E5 92 6D\n" +
      "     70 71 FD D4  BF A5 07 6D  4B 32 53 F8  DE 47 9E BD\n" +
      "     F5 35 76 76  F1 64 1B 2F  09 7E 9B 78  5E 9E 52 8E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   257 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78\n" +
      "Result:\n" +
      "     D4 0F E4 49  8F CC 2F 68  E6 71 75 C7  A5 D6 9C B0\n" +
      "     24 D5 84 3E  85 97 7D 0B  AE EC 48 52  02 A9 09 90\n" +
      "     FC 38 5A 13  08 97 3D 28  EF 2C FA 62  8F 1D CA CE\n" +
      "     31 42 63 4F  E0 3E 9F 78  01 A3 7D 11  61 72 27 E9\n" +
      "     D8 CA 35 1F  1D 6A B4 6D  0A CA 6E 38  C1 51 68 59\n" +
      "     63 9E DA E9  4A 9A 79 5C  F8 15 AD E8  55 C9 3B 3A\n" +
      "     8E D1 0D CE  D9 68 3E 42  A5 6F 17 EE  04 A7 E5 9E\n" +
      "     A4 E7 94 AF  06 8C DB 47  28 B9 05 22  5E B2 81 70\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   384 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "Result:\n" +
      "     31 10 5E 1E  F0 42 C3 0B  95 B1 6E 0F  6E 6A 1A 19\n" +
      "     17 2B B7 D5  4A 05 97 DD  0C 71 11 94  88 8E FE 1D\n" +
      "     BC E8 2D 47  41 6D F9 57  7C A3 87 21  9F 06 E4 5C\n" +
      "     D1 09 64 FF  36 F6 71 1E  DB BE A0 E9  59 5B 0F 66\n" +
      "     F7 2B 75 5D  70 A4 68 57  E0 AE C9 85  61 A7 43 D4\n" +
      "     93 70 D8 E5  72 E2 12 81  12 73 12 5F  66 CC 30 BF\n" +
      "     11 7D 32 21  89 4C 48 01  2B F6 E2 21  9D E9 1E 06\n" +
      "     4B 01 52 35  17 42 0A 1E  00 F7 1C 4C  C0 4B AB 62\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   511 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     EA B0 FB 29  7F 63 D0 5A  39 64 5A 8A  A4 E3 C6 B8\n" +
      "     B2 01 29 C2  09 83 1D 77  1C E0 BF 03  53 80 A2 5A\n" +
      "     92 23 D6 C4  E3 93 2D 9E  36 B7 4E C2  44 6C 75 DA\n" +
      "     93 62 73 33  41 85 72 5E  52 84 83 0B  96 EE C4 7E\n" +
      "     25 76 6F 7C  DF 99 01 0F  E0 BD DE E3  44 99 D3 25\n" +
      "     D2 23 C6 51  E4 23 9B B2  E5 83 7C BA  82 32 33 D9\n" +
      "     77 6F 49 F7  F8 E0 C3 1F  F7 A2 34 3D  E5 38 2B D3\n" +
      "     D4 C8 B9 1C  44 99 88 EF  C8 E8 C6 67  95 2C 38 8E\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   512 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "Result:\n" +
      "     50 43 2D D0  01 D0 A0 24  D8 0A 0B B3  69 47 B7 03\n" +
      "     86 AF F0 5F  BB 88 72 46  6D C7 DF 34  B3 1B 09 C4\n" +
      "     D5 E6 8C 72  96 83 07 F6  C3 43 AF 2E  DB 0F 25 DC\n" +
      "     64 31 23 C3  45 D3 5C 54  46 96 E5 D5  42 79 6E 92\n" +
      "     91 E7 1B E5  9E D2 F9 05  0D 51 73 3A  44 FA 21 06\n" +
      "     C7 F9 87 3B  C3 C2 B2 6C  DD 8B F7 7F  9A F3 06 F1\n" +
      "     1B F3 92 32  70 CA 25 5B  26 8F 58 92  54 6C D7 51\n" +
      "     54 BC 20 73  8E 8B B0 72  F3 A3 7D 9C  DB 30 D0 80\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   513 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7\n" +
      "Result:\n" +
      "     09 E6 DA 49  00 8B F5 E5  DB 2B 3B 24  19 92 AA 5E\n" +
      "     97 1D 55 6C  C5 27 84 A7  C5 AE 43 6C  34 26 D9 37\n" +
      "     F3 06 43 F9  12 35 D0 CD  A7 F8 50 E3  3B DD 33 B4\n" +
      "     78 93 4A 36  E6 90 19 21  61 4A D3 18  F9 35 4A 82\n" +
      "     08 B9 EF F7  13 0C F5 A2  56 0E 8F BC  F5 4D FA 15\n" +
      "     58 98 51 05  82 9F FE 66  23 3C F4 DD  D4 68 96 57\n" +
      "     2D 6C 9B 06  F2 53 2C 77  CD 1C 5B DC  24 7D 84 97\n" +
      "     0D 20 E1 2B  13 28 E8 67  49 23 8B 9F  E9 B1 A5 23\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =   768 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "Result:\n" +
      "     14 E9 85 66  4C 42 1E 0F  90 CB 2E 6A  3E BB 95 A6\n" +
      "     ED A9 C2 2B  5F 0E 3F D1  24 12 AA D2  50 DB D6 68\n" +
      "     01 15 AF DF  38 BA F2 0B  E4 55 01 2B  85 F5 B6 DC\n" +
      "     06 41 78 68  91 3E 49 53  E3 D3 54 5B  95 60 39 EF\n" +
      "     63 D5 6C 07  FA 0B EA FA  33 B2 06 2D  21 9B 93 49\n" +
      "     8F 15 24 EE  A7 64 CB 6A  5F 98 43 D4  51 A4 12 39\n" +
      "     81 DB 52 4E  B6 37 1F B8  63 10 A4 67  CF 69 62 D6\n" +
      "     E4 29 04 57  8A D1 84 61  CF A0 7D D2  BE D3 2A 0B\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1023 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     54 2F 2A BC  55 55 8F B4  0D E3 68 8D  3C DA 41 D2\n" +
      "     20 9B 9F 6C  F7 B3 CB 47  B3 65 02 3C  14 E9 00 2F\n" +
      "     B2 D5 8D 83  5D B8 30 07  F5 8E 60 AA  15 03 C9 49\n" +
      "     07 87 C0 B1  A1 E2 A9 21  8C 8B B1 D8  23 F9 05 D4\n" +
      "     65 87 09 1E  99 A2 2C 55  36 12 0C 5F  1F DC 65 F7\n" +
      "     75 22 90 AB  A2 37 85 B9  31 E9 8D 99  BF D5 0D B8\n" +
      "     E6 7E 93 40  4D 44 6F 50  AC CC 0B 79  11 84 8C 5D\n" +
      "     5A 99 00 60  7B 18 A3 2A  90 5F 48 4A  B2 52 B6 CF\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  160-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     2E 6A 4C BF  2E F0 5E A9  C2 4B 93 E8  D1 DE 73 2D\n" +
      "     DF 27 39 EB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  224-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     1D 6D E1 9F  37 F7 A3 C2  65 44 0E EC  B4 B9 FB D3\n" +
      "     30 0B B5 AC  60 89 5C FC  0D 4D 3C 72\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  256-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     98 6A 4D 47  2B 12 3E 81  48 73 1A 8E  AC 9D B2 33\n" +
      "     25 F0 05 8C  4C CB C4 4A  5B B6 FE 3A  8D B6 72 D7\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  384-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     9C 3D 06 48  C1 1F 31 C1  83 95 D5 E6  C8 EB D7 3F\n" +
      "     43 D1 89 84  3F C4 52 35  E2 C3 5E 34  5E 12 D6 2B\n" +
      "     C2 1A 41 F6  58 96 DD C6  A0 49 69 65  4C 2E 2C E9\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  512-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     5D 04 16 F4  9C 2D 08 DF  D4 0A 14 46  16 9D C6 A1\n" +
      "     D5 16 E2 3B  8B 85 3B E4  93 35 13 05  1D E8 D5 C2\n" +
      "     6B AC CF FB  08 D3 B1 65  16 BA 3C 6C  CF 3E 9A 6C\n" +
      "     78 FF F6 EF  95 5F 2D BC  56 E1 45 9A  7C DB A9 A5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     96 CA 81 F5  86 C8 25 D0  36 0A EF 5A  CA EC 49 AD\n" +
      "     55 28 9E 17  97 07 2E EE  19 8B 64 F3  49 CE 65 B6\n" +
      "     E6 ED 80 4F  E3 8F 05 13  5F E7 69 CC  56 24 0D DD\n" +
      "     A5 09 8F 62  08 65 CE 4A  42 78 C7 7F  A2 EC 6B C3\n" +
      "     1C 0F 35 4C  A7 8C 7C A8  16 65 BF CC  5D C5 42 58\n" +
      "     C3 B8 31 0E  D4 21 D9 15  7F 36 C0 93  81 4D 9B 25\n" +
      "     10 3D 83 E0  DD D8 9C 52  D0 05 0E 13  A6 4C 61 40\n" +
      "     E6 38 84 31  96 16 85 73  4B 1F 13 8F  E2 24 30 86\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  264-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     77 88 F7 FF  DE 89 F1 0A  31 6A 2E 1B  E3 B8 3C 45\n" +
      "     52 85 26 2A  C7 BD 61 79  22 EA 2C A3  56 9A CA 57\n" +
      "     C5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024:  520-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     4D D3 6D B8  FB BE 50 B1  EC FA 3B 99  1C 48 15 B2\n" +
      "     CE 1C C1 37  DA DC DF 0F  BA 7D F5 BD  02 0A 60 C5\n" +
      "     12 BE EA 0E  E3 F7 3D AD  B0 A8 CD 0F  14 96 8D C1\n" +
      "     FB 0D 8A B8  43 C3 C8 F6  AD 0E 6A 20  63 AC 7D 8B\n" +
      "     DC\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1032-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     F5 B7 ED EF  68 F3 41 03  41 F7 20 4A  41 56 78 A5\n" +
      "     44 1E DF 90  E1 B5 03 D5  D2 A3 4E E6  3B B8 CF A3\n" +
      "     AB 0E 42 C3  C6 F0 15 13  8C 03 3B 18  DB 16 63 C6\n" +
      "     7F 6A 56 18  59 89 C2 AE  2C CE 8E 85  9E FD B1 AB\n" +
      "     2D EC E2 3A  B9 46 67 BE  97 BE 39 C4  A4 C3 57 27\n" +
      "     7E DB 12 57  50 C6 50 B9  EA 63 8D 5C  9D 05 F1 E4\n" +
      "     FD 25 42 1E  AD 59 A8 F3  DD 14 B4 7A  B1 E7 51 35\n" +
      "     A3 8B 4C 87  96 2B C8 45  9F D5 B3 A9  80 41 87 B5\n" +
      "     72\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 2056-bit hash, msgLen =  1024 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "Result:\n" +
      "     56 A0 CA B1  AD 31 58 59  DA 7A 6C FC  35 80 7C BF\n" +
      "     E0 39 AF 06  CA 4B 86 71  C0 53 36 0B  DA 0B 17 C1\n" +
      "     4A 9E B5 EB  2A BB 01 B0  DB 3F 45 C0  3C D3 0C 69\n" +
      "     D7 C1 B7 0C  5C 9E F7 4C  06 FB 3A EF  0C 84 3C E9\n" +
      "     B4 C1 BA 22  94 DD B5 C7  1C AB 69 2C  ED C1 E6 F9\n" +
      "     08 C4 71 B3  8C 0C 58 34  18 B5 5A EF  DD FE 08 AB\n" +
      "     A4 05 5D 0D  19 ED B5 CC  BA 16 C3 E2  88 47 1E FE\n" +
      "     46 3E 6B F6  CC 34 6C C7  4F 6C 01 3E  02 93 E6 DF\n" +
      "     D2 E4 AA 66  A9 22 42 FD  39 5B 6D 91  AA AD 5A 07\n" +
      "     1C 44 9D 77  EA 00 E4 4E  CC 75 07 38  90 AC 50 D4\n" +
      "     F4 21 0E 8C  9D A4 53 85  A4 6D 21 4A  0F CC C1 31\n" +
      "     DB 3F 84 2F  95 5E 6E 76  AC 31 1B 3B  F4 39 DD 51\n" +
      "     9B ED D6 91  78 5A DF 75  40 F3 16 3A  D1 21 6C F2\n" +
      "     AD B7 D4 BF  40 D9 3B E3  18 4A EF 51  B6 51 CA 26\n" +
      "     C7 EC 44 07  3F 43 AD 68  9D 26 9E A9  FF 02 F8 D2\n" +
      "     C8 93 2F E6  CE D0 29 2F  97 FB 5F 07  CA 27 6D 6B\n" +
      "     43\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  1025 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1\n" +
      "Result:\n" +
      "     56 8F C4 1E  4B F1 88 D7  F9 DF 9D A1  A1 AA BF 45\n" +
      "     5E C9 8C 13  7D 5C BB 13  79 C3 6B BF  E3 18 B4 64\n" +
      "     EA 3A F9 0F  97 96 25 D3  B9 AC F0 EB  76 1B 1D 71\n" +
      "     A1 A8 6E 41  35 8D D3 52  B8 E8 29 6E  6A 7E BF 77\n" +
      "     86 17 2F 09  09 7F 27 EB  5C 22 A4 A0  A9 13 1C 9D\n" +
      "     D1 C4 DF DF  E0 BE 6C 88  46 C9 DB A3  3B 87 52 CA\n" +
      "     09 B3 58 C8  87 27 3D 87  63 6C 2C 37  2B 1A AD EE\n" +
      "     CD DA 1A 17  7A 68 8E 1A  08 2C 2B 75  35 49 CF BB\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2047 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     32 4E 70 F4  94 C9 CB D9  77 15 4C 07  68 37 F6 0A\n" +
      "     39 A2 E8 8D  97 BA 5F E0  80 E2 BE 42  0F E7 0E 50\n" +
      "     CC 51 9C 81  39 26 C4 48  5C 16 DB 4A  88 DB 3B 11\n" +
      "     C4 C6 B8 B1  4C 97 36 25  23 33 55 1B  CE 2C 23 0D\n" +
      "     EA 07 CA F2  DC AA 15 7A  F1 F2 BD 6F  57 99 FD BB\n" +
      "     31 8E E1 40  2C 93 A5 67  26 85 12 E1  CD 13 45 DA\n" +
      "     54 DA 1D EF  98 9F 89 91  3A D6 A1 2E  B9 8C 23 11\n" +
      "     2E A5 67 BB  F5 11 AE 6A  6A B4 27 8B  1F 97 61 3F\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2048 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "Result:\n" +
      "     9A C0 1B 49  82 55 E8 B2  8D BB B9 EF  72 17 82 FF\n" +
      "     A9 A2 A9 5C  A6 D8 E3 47  26 30 88 C4  4D 0F 96 26\n" +
      "     F9 1B A4 56  73 D0 2E EF  8A C5 EC 6B  33 EE B8 F5\n" +
      "     26 A9 1C BC  E2 91 3D 67  C2 75 25 FC  FD B7 9B 62\n" +
      "     6B C0 D6 B6  E9 49 56 DF  F2 86 F4 9D  31 52 0C 3A\n" +
      "     9E 39 D6 28  1E 94 41 4F  17 89 7B 18  D0 55 36 48\n" +
      "     37 FB DE B6  00 6A 19 2D  BC AB 72 5D  80 D3 B0 0B\n" +
      "     50 CD 02 CA  F6 5D 7E D6  55 AE FB 28  3B 03 3F C5\n" +
      "--------------------------------\n" +
      "\n" +
      ":Skein-1024: 1024-bit hash, msgLen =  2049 bits, data = 'random'\n" +
      "\n" +
      "Message data:\n" +
      "     FB D1 7C 26  B6 1A 82 E1  2E 12 5F 0D  45 9B 96 C9\n" +
      "     1A B4 83 7D  FF 22 B3 9B  78 43 94 30  CD FC 5D C8\n" +
      "     78 BB 39 3A  1A 5F 79 BE  F3 09 95 A8  5A 12 92 33\n" +
      "     39 BA 8A B7  D8 FC 6D C5  FE C6 F4 ED  22 C1 22 BB\n" +
      "     E7 EB 61 98  18 92 96 6D  E5 CE F5 76  F7 1F C7 A8\n" +
      "     0D 14 DA B2  D0 C0 39 40  B9 5B 9F B3  A7 27 C6 6A\n" +
      "     6E 1F F0 DC  31 1B 9A A2  1A 30 54 48  48 02 15 4C\n" +
      "     18 26 C2 A2  7A 09 14 15  2A EB 76 F1  16 8D 44 10\n" +
      "     E1 14 AA 47  F7 C5 C6 15  43 C4 D9 59  18 82 34 F7\n" +
      "     97 F4 5A 1D  16 65 E3 76  46 D8 12 9A  45 EE 70 78\n" +
      "     09 91 BB 6B  10 02 39 E4  66 D5 8D 4C  DD 9D 9D 01\n" +
      "     90 AB 64 47  0D DC 87 F5  E5 09 E9 A8  CF 82 4F 58\n" +
      "     EF 04 73 2E  AB 28 09 2D  18 A5 AD A4  5B 6D 49 FB\n" +
      "     0F 33 F4 CC  07 E3 9E C6  44 9E 8C 0A  BB 17 C6 58\n" +
      "     66 00 9A 3D  9C 31 C0 D7  65 E4 AF 88  B8 60 23 E9\n" +
      "     A0 67 E3 32  0C 09 24 6A  3F AE 8A 3F  D9 7C 48 7E\n" +
      "     4E\n" +
      "Result:\n" +
      "     0F 60 96 AC  DC E1 0F 72  04 48 F6 15  78 A7 87 A3\n" +
      "     A2 9C 3E F3  43 D8 19 23  C1 2C 4D C0  73 7E 05 A9\n" +
      "     71 3B A0 1E  8C 41 86 B3  3B 87 7D 55  E1 3E 38 FE\n" +
      "     2D F5 06 45  6A F1 74 FE  B8 B9 80 EB  9D 80 BA 2C\n" +
      "     96 30 BC CF  BD 9B 4C F5  01 DD 68 E2  3E 55 6D AD\n" +
      "     61 39 09 E1  08 30 7E AA  8C B6 25 22  21 01 A4 B2\n" +
      "     D1 B1 1E 7F  44 16 60 85  43 53 7C 27  4E F4 82 BC\n" +
      "     76 98 86 35  8A 73 0A 1B  5A 8F 17 30  C8 B6 71 C0\n" +
      "--------------------------------\n";















