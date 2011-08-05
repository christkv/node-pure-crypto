require.paths.unshift("./lib");

var TestSuite = testCase = require('../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../deps/nodeunit'),
  SkeinMac = require('mac/skeinmac').SkeinMac,
  // Skein = require('hash/skein').Skein,
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

  "Simple SkeinMac test":function(test) {
    var messages = [
      "D3090C72167517F7C7AD82A70C2FD3F6443F608301591E598EADB195E8357135BA26FEDE2EE187417F816048D00FC23512737A2113709A77E4170C49A94B7FDFF45FF579A72287743102E7766C35CA5ABC5DFE2F63A1E726CE5FBD2926DB03A2DD18B03FC1508A9AAC45EB362440203A323E09EDEE6324EE2E37B4432C1867ED696E6C9DB1E6ABEA026288954A9C2D5758D7C5DB7C9E48AA3D21CAE3D977A7C3926066AA393DBD538DD0C30DA8916C8757F24C18488014668A2627163A37B261833DC2F8C3C56B1B2E0BE21FD3FBDB507B2950B77A6CC02EFB393E57419383A920767BCA2C972107AA61384542D47CBFB82CFE5C415389D1B0A2D74E2C5DA851",
      "D3090C72167517F7C7AD82A70C2FD3F6443F608301591E598EADB195E8357135BA26FEDE2EE187417F816048D00FC23512737A2113709A77E4170C49A94B7FDFF45FF579A72287743102E7766C35CA5ABC5DFE2F63A1E726CE5FBD2926DB03A2DD18B03FC1508A9AAC45EB362440203A323E09EDEE6324EE2E37B4432C1867ED",
      "D3090C72167517F7C7AD82A70C2FD3F6443F608301591E598EADB195E8357135BA26FEDE2EE187417F816048D00FC23512737A2113709A77E4170C49A94B7FDFF45FF579A72287743102E7766C35CA5ABC5DFE2F63A1E726CE5FBD2926DB03A2DD18B03FC1508A9AAC45EB362440203A323E09EDEE6324EE2E37B4432C1867ED",
      "D3090C72167517F7C7AD82A70C2FD3F6443F608301591E598EADB195E8357135BA26FEDE2EE187417F816048D00FC23512737A2113709A77E4170C49A94B7FDFF45FF579A72287743102E7766C35CA5ABC5DFE2F63A1E726CE5FBD2926DB03A2DD18B03FC1508A9AAC45EB362440203A323E09EDEE6324EE2E37B4432C1867ED"
    ]
    
    var macs = [
      "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB875E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC814631346C",
      "CB41F1706CDE09651203C2D0EFBADDF8",
      "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E",
      "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E92"
    ]
  
    var digests = [
      "46A42B0D7B8679F8FCEA156C072CF9833C468A7D59AC5E5D326957D60DFE1CDFB27EB54C760B9E049FDA47F0B847AC68D6B340C02C39D4A18C1BDFECE3F405FAE8AA848BDBEFE3A4C277A095E921228618D3BE8BD1999A071682810DE748440AD416A97742CC9E8A9B85455B1D76472CF562F525116698D5CD0A35DDF86E7F8A",
      "A097340709B443ED2C0A921F5DCEFEF3EAD65C4F0BCD5F13DA54D7ED",
      "AC1B4FAB6561C92D0C487E082DAEC53E0DB4F505E08BF51CAE4FD5375E37FC04",
      "96E6CEBB23573D0A70CE36A67AA05D2403148093F25C695E1254887CC97F9771D2518413AF4286BF2A06B61A53F7FCEC"
    ]
    
    var states = [1024, 256, 256, 256];
    var outputs = [1024, 224, 256, 384];
    var messageLengths = [2048, 1024, 1024, 1024];
        
    for(var i = 0; i < messages.length; i++) {
      var message = util.hexStringToBinaryArray(messages[i]);
      var mac = util.hexStringToBinaryArray(macs[i]);
      var digest = util.hexStringToBinaryArray(digests[i]);
      var state = states[i];
      var output = outputs[i];
      var msgLen = messageLengths[i];
      
      var skeinmac = new SkeinMac();
      skeinmac.init(state, output, mac);
      skeinmac.updateBits(message, 0, msgLen);
      // Allocate output size for mac
      var output = new Array(skeinmac.getMacSize());
      // Calculare final mac
      skeinmac.doFinal(output, 0);
      test.deepEqual(output, digest);          
    }
    
    test.done();
  }, 

  "SkeinMac test vectors":function(test) {
    var vectors = parseMac(macString);
    
    for(var i = 0; i < vectors.length; i++) {
      var vector = vectors[i];
      
      // Unpack test vector
      var stateSize = vector.stateSize;
      var hashBitLength = vector.hashBitLength;
      var msgLength = vector.msgLength;
      var message = vector.message.length >= 2 ? util.hexStringToBinaryArray(vector.message) : [];
      var mac = util.hexStringToBinaryArray(vector.mac);
      var digest = util.hexStringToBinaryArray(vector.result);
        
      if(vector.mac.match(/\(none\)/) == null) {
        var skeinmac = new SkeinMac();
        skeinmac.init(stateSize, hashBitLength, mac);
        skeinmac.updateBits(message, 0, msgLength);

        // Allocate output size for mac
        var output = new Array(skeinmac.getMacSize());
        // Calculare final mac
        skeinmac.doFinal(output, 0);
        test.deepEqual(output, digest);          
      }
    }
    
    test.done();
  }  
});

var parseMac = function(text) {
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
    var _4 = defString.match(/data \= \'[a-z|\+|A-Z]*\'/g)[0].split(/=/)[1].trim().replace(/\'/g, '');
    // Get message
    lines.shift();
    lines.shift();
    // line
    var line = lines.shift();
    var messagedata = "";
    var result = "";
    var mac = "";

    while(line.match(/MAC/) == null) {
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

    while(line.match(/Result/) == null) {
      mac = mac + line.replace(/ */g, '');    
      line = lines.shift();
    }

    // Skip to next message
    // line = lines.shift();
    line = lines.shift();

    while(line.match(/--------------------------------/) == null) {
      result = result + line.replace(/ */g, '');    
      line = lines.shift();
    }
    
    vectors.push({stateSize:_1, hashBitLength:_2, msgLength:_3, message:messagedata, result:result, mac:mac});
  }
  
  return vectors;
}

var macString = "\n" +
  ":Skein-256:   256-bit hash, msgLen =     0 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "    (none)\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     88 6E 4E FE  FC 15 F0 6A  A2 98 96 39  71 D7 A2 53\n" +
  "     98 FF FE 56  81 C8 4D B3  9B D0 08 51  F6 4A E2 9D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     1 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     6F 1A EF 07  4E 32 44 5E  F3 06 6D F3  8E D4 6D D2\n" +
  "     B4 A4 B6 EE  CB AB CD 12  4E 92 F6 52  04 68 EA 02\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     2 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     19 95 72 E5  A0 8F B9 94  71 22 67 D2  91 D8 8C FD\n" +
  "     B9 AE 26 8E  6F FC C1 F2  48 0E 97 B9  D4 A7 08 00\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     3 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     EB C9 61 2F  20 64 D8 D8  98 02 4B B3  29 4B C7 14\n" +
  "     29 13 C3 12  38 87 6B 89  46 60 FA 52  EB 67 B7 84\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     4 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     D7 51 BA D4  D9 4F 07 49  39 E6 A1 63  E9 3A 71 E3\n" +
  "     21 7F EA 7F  7B AE 05 0F  48 94 3A AE  B7 59 E6 86\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     5 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     2D F6 B2 87  CA BC 25 EA  98 AB 3C F9  20 15 32 16\n" +
  "     9F 7D 84 B2  13 2A 1C 78   12 CA 41 BC  01 61 8E 90\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     6 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     84 77 27 D4  62 A4 05 8F  5D 69 58 29  B1 50 04 1D\n" +
  "     28 E6 D2 30  26 89 7F AD  87 26 89 5B  22 C8 3A D4\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     7 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     30 E4 1F 05  17 37 73 FF  D3 98 CA A7  80 10 70 F7\n" +
  "     01 C6 12 BF  D0 35 F5 55  12 81 5C A8  91 28 18 CD\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     8 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     97 94 22 A9  4E 3A FA A4  66 64 12 4D  4E 5E 8B 94\n" +
  "     22 B1 D8 BA  F1 1C 6A E6  72 59 92 AC  72 A1 12 CA\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =     9 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     5F 07 9A 98  3F 3C 22 2B  89 52 BF 6B  75 62 3E A4\n" +
  "     E6 4A 35 3B  0F 8F A0 66  F8 E3 FF 0F  78 B6 0F 2D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =    10 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     9D 85 D6 FC  F8 DF 1F 78  CB 60 27 F1  D5 2D FF F9\n" +
  "     D5 B5 D1 98  73 B6 6C 6F  4D F9 5B 77  B1 4E 47 CB\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =    32 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     1D 65 83 72  CB EA 2F 99  28 49 3C C4  75 99 D6 F4\n" +
  "     AD 8C E3 35  36 BE DF A2  0B 73 9F 07  51 65 19 D5\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =    64 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     41 EF 6B 0F  0F AD 81 C0  40 28 4F 3B  1A 91 E9 C4\n" +
  "     4E 4C 26 A6  D7 20 7F 3A  AC 43 62 85  6E F1 2A CA\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   128 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     CA 82 08 11  9B 9E 4E 40  57 63 1A B3  10 15 CF D2\n" +
  "     56 F6 76 3A  0A 34 38 16  33 D9 7F 64  08 99 B8 4F\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   192 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     DC BD 5C 8B  D0 90 21 A8  40 B0 EA 4A  AA 2F 06 E6\n" +
  "     7D 7E EB E8  82 B4 9D E6  B7 4B DC 56  B6 0C C4 8F\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   255 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     5C 62 1E 94  C8 74 15 F2  C2 18 29 E8  04 C3 94 15\n" +
  "     EB 6C AA EC  28 DA F4 12  62 CC 25 62  E9 F7 F5 71\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   256 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     9E 99 80 FC  C1 6E E0 82  CF 16 4A 51  47 D0 E0 69\n" +
  "     2A EF FE 3D  CB 8D 62 0E  2B B5 42 09  11 62 E2 E9\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   257 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     22 E2 2B 53  88 E3 CA BC  CE 3D 34 52  9B 2E BE D7\n" +
  "     6F 89 33 27  9C 05 3B F8  2B 97 31 F6  7D 1C 1F 83\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   384 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     C3 53 A3 16  55 8E C3 4F  82 45 DD 2F  9C 2C 49 61\n" +
  "     FB C7 DE CC  3B 69 05 3C  10 3E 4B 8A  AA F2 03 94\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   511 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     94 0D FA A7  36 D4 1F 6C  C9 73 0A 74  2F EC 44 44\n" +
  "     6E 1F 42 C5  37 D7 A4 13  17 23 5A 04  C6 B0 0B A0\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   512 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     B1 B8 C1 81  88 E6 9A 6E  CA E0 B6 01  8E 6B 63 8C\n" +
  "     6A 91 E6 DE  68 81 E3 2A  60 85 84 68  C1 7B 52 0D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   513 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     7F 72 5A 25  79 36 F6 19  09 28 94 1F  75 D2 83 AB\n" +
  "     B6 11 88 64  52 F1 65 76  8F B5 EE 7E  5F A6 B4 98\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =   768 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     1D FD 25 15  A4 12 E7 88  52 CD 81 A7  F2 16 77 11\n" +
  "     B4 CA 19 B2  89 1C 2E A3  6B A9 4F 84  51 94 47 93\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  1023 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     5E 33 17 92  1D B4 1B 2C  F1 82 87 F4  0E 74 DA 5D\n" +
  "     C4 45 9E 1E  F2 90 3E D3  7D 13 A8 DE  0F FF 9F 2A\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   160-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     49 82 E9 E2  81 C1 3F 11  17 13 48 16  A7 B8 58 E8\n" +
  "     F1 2F B7 29\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   224-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     A0 97 34 07  09 B4 43 ED  2C 0A 92 1F  5D CE FE F3\n" +
  "     EA D6 5C 4F  0B CD 5F 13  DA 54 D7 ED\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     AC 1B 4F AB  65 61 C9 2D  0C 48 7E 08  2D AE C5 3E\n" +
  "     0D B4 F5 05  E0 8B F5 1C  AE 4F D5 37  5E 37 FC 04\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   384-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     96 E6 CE BB  23 57 3D 0A  70 CE 36 A6  7A A0 5D 24\n" +
  "     03 14 80 93  F2 5C 69 5E  12 54 88 7C  C9 7F 97 71\n" +
  "     D2 51 84 13  AF 42 86 BF  2A 06 B6 1A  53 F7 FC EC\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   512-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     0E 95 E5 97  E7 1D 63 50  F2 0B 99 C4  17 9F 54 F4\n" +
  "     3A 47 22 70  5C 06 BA 76  5A 82 CB 0A  31 4F E2 FE\n" +
  "     87 EF 80 90  06 3B 75 7E  53 18 27 06  ED 18 73 7D\n" +
  "     AD C0 DA 1E  1C 66 51 8F  08 33 40 52  70 2C 5E D7\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:  1024-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     CA 1A FA C5  76 2D A7 C2  CC 66 8C 71  A4 D9 85 5E\n" +
  "     F1 B7 9C E0  C5 5A 19 BD  34 6D B3 13  73 0B 0B B7\n" +
  "     36 21 D7 7F  78 87 57 3C  6C 08 72 4B  95 08 D6 FD\n" +
  "     6C E3 34 60  D6 2C 0D 53  E2 60 D8 D4  D4 34 66 84\n" +
  "     9E F8 72 31  03 29 F6 3C  2C 64 87 4A  BC 64 3F 30\n" +
  "     33 8A 2A 49  63 C2 22 99  BC 1A 85 E4  B3 E5 03 DF\n" +
  "     39 44 2A EA  B7 E5 12 6F  20 96 4E 00  A7 1D A8 34\n" +
  "     45 C5 57 F4  5F 05 45 8E  E9 8F 94 92  FE F5 41 F5\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   264-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     06 4A BD 48  96 F4 60 B1  95 3F 5A 35  7E 7F 7C 52\n" +
  "     56 E2 9C DB  62 B8 74 0D  0B 52 29 5C  FA 2E F4 C7\n" +
  "     A2\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   520-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     ED F2 20 E4  3E 04 86 03  BD 16 19 7D  59 B6 73 B9\n" +
  "     97 4D E5 B8  BC F7 CB 15  58 A4 79 9F  6F D3 74 3E\n" +
  "     B5 FB 40 0C  D6 12 9A FC  0C 60 E7 B7  41 B7 E5 80\n" +
  "     6F 0E 0B 93  EB 84 29 FB  C7 EF A2 22  17 5A 9C 80\n" +
  "     FD\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:  1032-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     F3 F5 9F B0  73 99 C7 B7  3A AE 02 A8  59 08 83 CB\n" +
  "     2F DF DE 75  C5 56 54 E7  18 46 52 23  01 BD E4 8D\n" +
  "     26 71 69 AD  CC 55 9E 03  8E 8C 2F 28  FA A5 52 B5\n" +
  "     50 D5 18 74  05 53 84 AD  EA 93 C0 36  C7 1A 1F 0A\n" +
  "     F0 C7 BC C3  BC 92 37 38  D5 30 7B 9D  A7 CB 42 3D\n" +
  "     4E 61 5C 62  9C 4A BA 71  F7 0D 4C 9D  1F A0 08 17\n" +
  "     68 25 E5 1B  FA 02 03 44  5A 40 83 94  7E C1 9F 6A\n" +
  "     0F BD 08 2B  5B 97 0F 23  96 FB 67 42  06 39 41 04\n" +
  "     47\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:  2056-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     80 EB 80 D9  B8 83 6B 32  FA 57 6F C8  4B A0 8E DF\n" +
  "     BD FD 69 79  12 3D 61 91  4E 61 0A 70  A3 72 B3 7F\n" +
  "     56 0A 10 90  94 84 F9 F4  A3 77 C9 3E  29 BA 68 1D\n" +
  "     FE 52 2C 41  DC 83 B5 EE  05 67 E5 37  00 07 C7 BB\n" +
  "     E4 DF 0B 2B  4A 25 E0 88  F8 0D 72 FC  30 73 4C DC\n" +
  "     D7 6D 81 7B  42 FB D4 4D  CA 88 10 19  AF B2 53 06\n" +
  "     F1 9D 4E 91  84 87 78 AF  30 65 17 D2  07 2C EF 72\n" +
  "     CA A3 27 E8  77 C5 B6 55  4F 83 CE C3  D0 08 77 13\n" +
  "     1B 47 C4 D3  B5 57 F5 A1  35 41 C4 D5  08 0E E3 CE\n" +
  "     7A 65 89 93  D0 83 EF D0  DB 34 96 A8  75 20 60 C3\n" +
  "     C8 55 2F 44  B2 90 CA BD  CC 86 7F 69  1A D6 05 83\n" +
  "     6C 08 DB D5  9C 95 28 D8  85 B6 00 B8  5F DF C8 A9\n" +
  "     D0 E6 36 AC  3A D8 B4 29  5B CB 01 69  E7 8D C3 58\n" +
  "     E7 7E AC C8  C4 B6 1B DD  FA 9E 5F 32  D2 26 8A 00\n" +
  "     6C FE 05 C5  71 50 FE 8E  68 CA BD 21  CF 6C F6 03\n" +
  "     5A A1 FE 4D  B3 6C 92 2B  76 5A AD 0B  64 E8 2A 2C\n" +
  "     37\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  1025 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     49 65 F9 5E  F1 D8 8C BD  0A EF 94 95  3B 83 7C B5\n" +
  "     52 EA E1 CF  92 2D EA 32  E9 93 4B EC  34 3B D9 27\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  2047 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =   16 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "Result:\n" +
  "     7B 1E 7D 0B  EE 84 BD 74  E0 46 1A 4F  1A 04 8A F0\n" +
  "     95 FD 22 74  3C 52 27 20  CF 95 EA 0F  46 00 D6 D2\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  2048 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     8F 88 DE 68  F0 3C D2 F3  96 CC DD 49  C3 A0 F4 FF\n" +
  "     15 BC DA 7E  B3 57 DA 97  53 F6 11 6B  12 4D E9 1D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-256:   256-bit hash, msgLen =  2049 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "     FD\n" +
  "MAC key =   33 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92\n" +
  "Result:\n" +
  "     4F FB B8 1F  77 D5 0C 12  32 A0 C9 E8  E0 CE 5A BD\n" +
  "     3A 7C B3 84  96 4F 81 6B  7C 41 FC 74  6B C9 A3 0C\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     0 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "    (none)\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     9B D4 3D 2A  2F CF A9 2B  EC B9 F6 9F  AA B3 93 69\n" +
  "     78 F1 B8 65  B7 E4 43 38  FC 9C 8F 16  AB A9 49 BA\n" +
  "     34 02 91 08  28 34 A1 FC  5A A8 16 49  E1 3D 50 CD\n" +
  "     98 64 1A 1D  08 83 06 2B  FE 2C 16 D1  FA A7 E3 AA\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     1 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     54 EA EA 3E  D9 F3 34 01  BA 8A F6 45  B3 D3 80 FC\n" +
  "     40 2E 61 B4  3B 84 ED 26  B3 D1 E9 80  72 A4 B0 29\n" +
  "     CA D8 6E DB  DC 17 34 3B  AD A6 27 0D  9E EB B0 44\n" +
  "     17 25 AF EA  51 AD 74 F0  43 CD 25 4B  BC CE 2C B7\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     2 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     F2 5C F3 31  24 D4 D1 D7  19 F4 3F BF  4E F4 F3 4B\n" +
  "     F2 5B 54 63  CD C6 8C B5  00 30 4C D5  CC 20 57 FC\n" +
  "     5A 3F 67 2E  7C 5C 2A C8  E9 17 CA CB  30 8F 46 AB\n" +
  "     97 00 D4 43  DE BF 61 36  13 31 A6 C7  94 2E 11 11\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     3 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     9A B9 1B BE  B1 56 18 9A  AA 8C 26 86  E5 07 56 83\n" +
  "     86 AE B6 38  70 D6 8B 0A  64 D3 C9 6B  C3 A5 10 33\n" +
  "     81 A3 DB 2D  EA 47 E6 A1  DE 5B 90 04  BC 62 57 68\n" +
  "     74 CD AF B0  5B 66 97 E3  5F 53 E2 2E  59 E9 0B FE\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     4 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     BB 66 8A B9  EC 0E 7C 28  94 78 75 66  49 BB AA C0\n" +
  "     0A D4 2F DB  E2 2C DE 8E  DD E7 E0 49  6A 02 B5 16\n" +
  "     0A 12 FE FB  BB E3 F0 70  10 04 77 01  69 42 86 D5\n" +
  "     25 17 C8 2C  87 EB 9C 0F  49 0F 8D 57  DB 6A 9A 99\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     5 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     1F FC F4 3B  12 50 42 A2  79 0C A4 5D  9C E7 F0 81\n" +
  "     30 FB 17 F8  A0 C2 87 7A  7E 1A 67 70  6A 51 91 0E\n" +
  "     A2 18 6A 81  49 2A 23 C2  65 77 8C F5  69 D9 32 42\n" +
  "     57 B6 52 DD  3D 36 A4 A7  DB 21 92 08  D1 A8 90 91\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     6 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     05 B7 34 EF  18 FE 9F 4E  B8 46 D9 3B  34 21 82 56\n" +
  "     28 DE 97 FE  F4 F6 D9 B4  4D 6A F9 DA  A1 9C DC E5\n" +
  "     5D A3 91 92  26 8A 48 42  3E 84 B0 42  93 F0 C2 76\n" +
  "     00 67 E5 51  A3 BC 2B F4  15 EA 77 64  1A 34 9B D7\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     7 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     B1 AB EB 7D  24 4E D1 84  98 87 52 18  85 76 78 BA\n" +
  "     CC 0C F2 99  17 42 E3 7F  36 3B 8C B8  ED 7F 70 46\n" +
  "     42 8C 07 9C  02 69 D0 C7  13 D8 A5 CD  F2 EE 23 D6\n" +
  "     A9 DE D6 E2  AF 48 EB 04  0D FA 5F 64  FD B4 D4 79\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     8 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     F0 C0 A1 0F  03 1C 8F C6  9C FA BC D5  41 54 C3 18\n" +
  "     B5 D6 CD 95  D0 6B 12 CF  20 26 44 02  49 22 11 EE\n" +
  "     01 0D 5C EC  C2 DC 37 FD  77 2A FA C0  59 6B 2B F7\n" +
  "     1E 60 20 EF  2D EE 7C 86  06 28 B6 E6  43 ED 9F F6\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =     9 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     55 8C C9 9D  D6 C6 41 06  2F 0C 0A 11  D4 1F 1D 08\n" +
  "     EA 28 D7 45  B6 91 37 46  D1 21 97 FC  3A BC C2 10\n" +
  "     45 BF A5 95  30 76 CE 5F  5C ED 95 9A  61 C0 03 D2\n" +
  "     45 CC FC AE  12 6F 76 5D  D4 75 FA B4  6C A8 9A A6\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =    10 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     C0 B0 D9 9D  0F 00 F5 20  39 B9 DC D8  B7 00 13 37\n" +
  "     7E 86 90 AF  DD 18 97 09  C7 2A 02 29  E6 8D 01 CC\n" +
  "     06 59 82 D0  DB 6A 8C FC  29 82 F7 DD  74 7C A3 73\n" +
  "     A8 41 34 9C  42 25 B9 EA  FF 9F B7 6E  03 8B B9 4E\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =    32 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     12 59 AF C2  CB 02 5E EF  2F 68 1E 12  8F 88 9B BC\n" +
  "     E5 7F 9A 50  2D 57 D1 A1  72 39 A1 2E  71 60 35 59\n" +
  "     16 B7 22 23  79 0F D9 A8  B3 67 EC 96  21 2A 3E D2\n" +
  "     39 33 1E D7  2E F3 DE B1  76 85 A8 D5  FD 75 15 8D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =    64 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     0C 1F 19 21  25 3D D8 E5  C2 D4 C5 F4  09 9F 85 10\n" +
  "     42 D9 11 47  89 27 05 82  91 61 F5 FC  64 D8 97 85\n" +
  "     22 6E B6 E1  87 06 84 93  EE 4C 78 A4  B7 C0 F5 5A\n" +
  "     8C BB B1 A5  98 2C 2D AF  63 8F C6 A7  4B 16 B0 D7\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   128 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     47 8D 7B 6C  0C C6 E3 5D  9E BB DE DF  39 12 8E 5A\n" +
  "     36 58 5D B6  22 28 91 69  2D 17 47 D4  01 DE 34 CE\n" +
  "     3D B6 FC BA  B6 C9 68 B7  F2 62 0F 4A  84 4A 29 03\n" +
  "     B5 47 77 55  79 99 37 36  D2 49 3A 75  FF 67 52 A1\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   192 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     13 C1 70 BA  C1 DE 35 E5  FB 84 3F 65  FA BE CF 21\n" +
  "     4A 54 A6 E0  45 8A 4F F6  EA 5D F9 19  15 46 8F 4E\n" +
  "     FC D3 71 EF  FA 89 65 A9  E8 2C 53 88  D8 47 30 49\n" +
  "     0D CF 39 76  AF 15 7B 8B  AF 55 06 55  A5 A6 AB 78\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   255 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     4A 02 CE 60  81 8D C9 48  60 6C 10 4F  0A 4D 59 8F\n" +
  "     E1 95 60 B6  BE 1D 37 C8  22 E2 C8 D5  B5 40 E1 FD\n" +
  "     B8 EC D0 A1  9B 58 26 77  97 B8 F8 1F  37 3E ED C6\n" +
  "     C7 92 6E 48  3A 4F E0 BC  F1 A9 85 DD  3E 0B AD E7\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   256 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     71 CB 34 2E  5A BE 90 A4  06 7D 5C E3  1F 8A 67 BF\n" +
  "     A1 B9 39 87  49 30 6F 1B  02 D4 E4 32  32 25 A9 98\n" +
  "     02 8A 43 0C  F4 76 5F 76  90 0D A2 6C  22 40 57 49\n" +
  "     03 9B 1D A3  78 30 22 4D  0F A0 74 1B  0D A0 45 58\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   257 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     B9 85 4E 1C  92 3E 52 12  D9 C1 13 DC  46 A5 11 0A\n" +
  "     75 44 16 EB  48 74 86 50  73 9F 3E D7  A2 41 AD BF\n" +
  "     71 8B 53 4A  59 16 35 F7  55 A8 1E ED  C2 BD 28 7D\n" +
  "     40 E3 D6 6D  F7 43 25 FA  2E DA 9B BB  01 E4 1B 17\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   384 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     A9 47 81 25  29 A7 2F D3  B8 96 7E C3  91 B2 98 BE\n" +
  "     E8 91 BA BC  84 87 A1 EC  4E A3 D8 8F  6B 2B 5B E0\n" +
  "     9A C6 A7 80  F3 0F 8E 8C  3B BB 4F 18  BC 30 2A 28\n" +
  "     F3 E8 7D 17  0B A0 F8 58  A8 FE FE 34  87 47 8C CA\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   511 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     95 E2 CE 7D  27 28 D2 A8  C3 F7 FB F9  4C F9 F8 EB\n" +
  "     E3 CA DD DE  9B EA CE DE  1E 3E 68 E9  2A 01 9B 5F\n" +
  "     16 25 41 D9  4C 2A 9C 6F  26 31 06 78  12 CA 75 9E\n" +
  "     86 6A 7B D0  23 1E DC AB  DA E0 D9 6B  1E B1 F6 9B\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   512 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     76 90 BA 61  F1 0E 0B BA  31 29 80 B0  21 2E 6A 9A\n" +
  "     51 B0 E9 AA  DF DE 7C A5  35 75 4A 70  6E 04 23 35\n" +
  "     B2 91 72 AA  E2 9D 8B AD  18 EF AF 92  D4 3E 64 06\n" +
  "     F3 09 8E 25  3F 41 F2 93  1E DA 59 11  DC 74 03 52\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   513 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     0F 12 07 D6  E6 BD F5 0C  B6 53 98 24  B2 83 C6 94\n" +
  "     02 0C 71 2B  39 F9 68 87  C2 04 38 A5  6E E6 A0 87\n" +
  "     65 56 B2 29  FF DE FC 39  F3 FF 4E 07  0B 37 A3 5E\n" +
  "     30 0D 95 92  6A 75 18 1C  B3 CC 3E B1  48 4D 73 53\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =   768 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     D1 0E 3B A8  18 55 AC 08  7F BF 5A 3B  C1 F9 9B 27\n" +
  "     D0 5F 98 BA  22 44 11 38  02 62 25 D3  4A 41 8B 93\n" +
  "     FD 9E 8D FA  F5 12 07 57  45 1A DA BE  05 0D 0E B5\n" +
  "     9D 27 1B 0F  E1 BB F0 4B  AD BC F9 BA  25 A8 79 1B\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  1023 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     78 8B 87 2E  B2 53 EA 46  DC 09 58 74  5F F9 95 53\n" +
  "     0C 96 4E 28  5D D7 F4 9E  CA E6 77 9E  57 CD 72 48\n" +
  "     63 A6 FB 7C  62 81 F8 7A  E4 4F 79 DF  3D 8E 34 58\n" +
  "     EF 7E 52 6D  B2 28 CA 09  77 86 E5 06  0E C9 AA 10\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   160-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     56 70 B2 26  15 65 70 DF  F3 EF E1 66  61 AB 86 EB\n" +
  "     24 98 2C DF\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   224-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     C4 1B 9F F9  75 3E 6C 0F  8E D8 88 66  E3 20 53 5E\n" +
  "     92 7F E4 DA  55 2C 28 98  41 A9 20 DB\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   256-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     AA 70 3B 79  8B 6F 47 2B  AA 9D 1E 16  89 FA 0F 70\n" +
  "     F8 DC A2 5A  60 46 BB 2C  8F B7 F3 44  07 93 4A E4\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   384-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     DF BF 5C 13  19 A1 D9 D7  0E FB 2F 16  00 FB CF 69\n" +
  "     4F 93 59 07  F3 1D 24 A1  6D 6C D2 FB  2D 78 55 A7\n" +
  "     69 68 17 66  C0 A2 9D A7  78 EE D3 46  CD 1D 74 0F\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     04 D8 CD DB  0A D9 31 D5  4D 19 58 99  A0 94 68 43\n" +
  "     44 E9 02 28  60 37 27 28  90 BC E9 8A  41 81 3E DC\n" +
  "     37 A3 CE E1  90 A6 93 FC  CA 61 3E E3  00 49 CE 7E\n" +
  "     C2 BD FF 96  13 F5 67 78  A1 3F 8C 28  A2 1D 16 7A\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:  1024-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     08 FC A3 68  B3 B1 4A C4  06 67 6A DF  37 AC 9B E2\n" +
  "     DB B8 70 4E  69 40 55 A0  C6 33 11 84  D4 F0 07 00\n" +
  "     98 F2 3F 09  63 EE 29 00  24 95 77 1B  F5 6F B4 D3\n" +
  "     D9 FF 35 06  AB CD 80 BE  92 73 79 F7  88 0D 5D 77\n" +
  "     03 91 9F BF  92 18 4F 49  8A C4 4F 47  F0 15 CE 67\n" +
  "     6E DE D9 16  5D 47 D5 37  33 F5 A2 7A  BB C0 5F 45\n" +
  "     AC D9 8B 97  CC 15 FF DC  ED 64 1D EF  D1 A5 11 9E\n" +
  "     F8 41 B4 52  A1 B8 F9 4E  E6 90 04 46  6C CD C1 43\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   264-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     66 9E 77 0E  BE 7E AC C2  B6 4C AA F0  49 92 3A D2\n" +
  "     97 A5 B3 7C  FA 61 C2 83  39 2D 81 CC  FC B9 BB BC\n" +
  "     09\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   520-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     94 AB 5C 2D  09 BC B9 8E  FE 25 49 79  9D C2 59 DD\n" +
  "     FE 16 E5 67  57 E0 4A 9A  F9 39 CA FC  D8 78 2B 46\n" +
  "     02 6B 42 A5  17 8A 53 F6  32 09 26 73  57 86 04 72\n" +
  "     4C CC C7 23  BE 50 A3 69  02 EE 00 48  D6 CD BC 9B\n" +
  "     43\n" +
  // "--------------------------------\n" +
  // "\n" +
  // ":Skein-512:  1032-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  // "\n" +
  // "Message data:\n" +
  // "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  // "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  // "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  // "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  // "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  // "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  // "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  // "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  // "MAC key =   32 bytes:\n" +
  // "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  // "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  // "Result:\n" +
  // "     AC C2 E0 3F  07 F3 3E 98  20 A6 03 84  21 08 94 29\n" +
  // "     AD CD 6A 7A  83 F7 33 BE  EC 04 8C 05  BF 37 53 1A\n" +
  // "     17 0A 55 37  FC B5 65 C3  48 A7 0A 83  21 7F 8B E7\n" +
  // "     68 FF 6F 95  FD 2B 3D 89  CB 7D 8A 3D  C8 49 50 5E\n" +
  // "     37 10 EB 4E  65 A8 E7 13  4B BF 58 0D  92 FE 18 C9\n" +
  // "     AA 98 75 63  66 9B 1F 01  4A A5 E0 92  51 90 89 35\n" +
  // "     55 34 EA A9  F0 BD C9 9F  68 39 F5 40  80 FF E7 46\n" +
  // "     23 25 4C 90  6E CB 88 96  B4 34 6C 31  78 A0 BC 28\n" +
  // "     98\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:  2056-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     9F 3E 08 22  23 C4 30 90  A4 A3 FF BD  CD 46 9C BA\n" +
  "     BF E0 C1 39  9D 1E DF 45  A5 DF C1 8F  4D B5 42 89\n" +
  "     28 A7 6E 97  9B 8D 0D 5D  FF EC 0E 6A  59 AD A4 48\n" +
  "     C1 FF BC 06  CC 80 A2 00  6F 00 2A DC  0C 6D BF 45\n" +
  "     85 63 76 22  28 DC E4 38  19 44 E4 60  EB EB FE 06\n" +
  "     F1 23 70 93  63 46 25 10  74 69 A2 2A  18 9A 47 F8\n" +
  "     B0 25 89 92  65 D8 89 0A  1B 39 DF 64  55 23 94 37\n" +
  "     7E 88 BA 2A  D4 4A 8C 8D  17 4F 88 4A  C8 C3 AE 24\n" +
  "     DD B0 AF FC  A5 FC EB 6A  A7 6E 09 70  68 81 E8 37\n" +
  "     17 74 B9 B0  50 A6 9B 96  EF 5E 97 E8  10 43 F8 B7\n" +
  "     E9 47 9E 28  7A B4 41 BA  CD 62 CA F7  68 A8 2C 8C\n" +
  "     3E 31 07 BE  70 EB 87 99  A3 98 56 FE  29 84 2A 04\n" +
  "     E2 5D E0 EF  9D E1 B7 E6  5B D0 F1 F7  30 68 35 28\n" +
  "     7F C9 57 38  8E 20 35 B7  D2 2D 3A A9  C0 6A 9F EF\n" +
  "     BC A1 6F 3F  60 E1 C4 DE  F8 90 38 D9  18 94 21 52\n" +
  "     A0 69 AA 2E  0B E8 AE 74  75 D8 59 03  1A DE C8 45\n" +
  "     83\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  1025 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69\n" +
  "MAC key =   65 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93\n" +
  "Result:\n" +
  "     5B F0 83 3B  11 C5 4D DE  59 35 44 09  33 21 62 25\n" +
  "     E9 38 74 E1  04 80 E8 31  B4 C1 EB B5  93 B6 94 7C\n" +
  "     17 E7 57 EF  7F FC E5 84  1E 03 28 05  00 71 84 87\n" +
  "     44 3E 11 AE  57 18 84 03  C1 C6 15 64  DE 10 36 F0\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  2047 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     51 65 C7 CF  26 A5 38 67  2A FB 26 99  12 34 82 EF\n" +
  "     66 7C AE F9  12 84 1C 06  5A 58 7E 33  36 07 88 C0\n" +
  "     CF 6F 29 E2  A2 C9 19 D9  2D 40 AB 9A  D1 EC 90 1F\n" +
  "     0B 9C 81 05  FC 08 52 AD  51 FD CD 11  FF D6 D0 B2\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  2048 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     FF 20 E5 C4  CA C9 AC 1E  B8 91 13 00  D4 AD AA AD\n" +
  "     55 F6 B0 6E  A1 86 4F AA  76 A6 25 C1  C5 8A 03 02\n" +
  "     3D 8B 99 9C  85 77 58 17  F3 4A 02 66  0F 9C 33 DD\n" +
  "     4D B5 D4 99  0B A2 F5 7C  15 C1 A5 6D  77 40 78 82\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-512:   512-bit hash, msgLen =  2049 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "     FD\n" +
  "MAC key =   32 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "Result:\n" +
  "     C7 85 B3 78  A7 37 60 8B  C6 74 63 D7  83 F8 2F A6\n" +
  "     50 72 56 DA  D2 10 5A 10  0C C3 6B DC  6A ED F3 60\n" +
  "     16 D3 77 7A  EA 62 B1 B1  78 EE 9B 8B  5C 91 DB 66\n" +
  "     A2 FC B9 5E  1A A0 9C 65  42 8F 26 EA  F0 21 BB E0\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     0 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "    (none)\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     BC F3 7B 34  59 C8 89 59  D6 B6 B5 8B  2B FE 14 2C\n" +
  "     EF 60 C6 F4  EC 56 B0 70  24 80 D7 89  3A 2B 05 95\n" +
  "     AA 35 4E 87  10 2A 78 8B  61 99 6B 9C  BC 1E AD E7\n" +
  "     DA FB F6 58  11 35 57 2C  09 66 6D 84  4C 90 F0 66\n" +
  "     B8 00 FC 4F  5F D1 73 76  44 89 4E F7  D5 88 AF C5\n" +
  "     C3 8F 5D 92  0B DB D3 B7  38 AE A3 A3  26 7D 16 1E\n" +
  "     D6 52 84 D1  F5 7D A7 3B  68 81 7E 17  E3 81 CA 16\n" +
  "     91 15 15 2B  86 9C 66 B8  12 BB 9A 84  27 53 03 F0\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     1 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     CC D2 D1 DE  BF 11 C7 01  5E FE EE EC  0D 81 CF 83\n" +
  "     80 C5 4F 26  B4 DD EB B1  EC 3F 86 48  4C B6 E1 A0\n" +
  "     B0 6B A2 D7  B5 5A 99 BD  8C 89 06 09  91 EF E7 E9\n" +
  "     A9 B3 ED FD  E0 C1 10 C3  48 43 94 09  92 6B 8D D3\n" +
  "     C7 94 A1 4D  FA AB AA AA  6E EA 48 3B  C4 BF 66 51\n" +
  "     BD DC BA 43  70 8B 3A 83  FA 8F CD AA  2A 26 0B 61\n" +
  "     9F 07 A8 CA  AD 67 BB F6  3F BA 7B 2C  71 56 83 18\n" +
  "     20 9B AA BE  7A FC 79 89  69 DF 30 6C  39 77 72 22\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     2 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     A5 40 17 16  DF 05 E9 38  EB F8 E1 15  9E 9C 9E DE\n" +
  "     10 6D B9 8B  60 1D 1B 29  7A 04 3F 36  D1 A0 32 F1\n" +
  "     CA 35 11 53  9D A9 84 79  E0 7D 0D 03  B9 50 18 39\n" +
  "     AB 54 69 66  9E 5D 92 F8  34 96 C8 D1  66 53 7B BC\n" +
  "     57 F7 04 3B  D8 A6 DD 21  BB 13 09 EB  77 DB BA 94\n" +
  "     C0 E3 ED 54  97 FF D7 B8  57 E2 ED FF  5A 57 A4 33\n" +
  "     01 67 7E BD  58 06 C5 1F  1F 88 6C 47  5A 4D EA D1\n" +
  "     38 37 6A 4E  88 C4 AE 8C  C4 9D B7 26  5E 37 88 35\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     3 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     33 01 92 3D  F9 97 D0 A4  A4 93 D6 BB  75 B0 1D 89\n" +
  "     62 8F F9 A3  9F F9 40 04  5B 52 28 C7  0D 41 6B 50\n" +
  "     CC 00 D5 6A  E0 93 04 56  D3 1A 43 6A  3C C9 CF E8\n" +
  "     B1 4E 0D 71  58 B4 26 E5  63 12 30 D5  CC 41 35 C2\n" +
  "     66 72 33 0F  94 FC 14 36  56 9A FE 52  72 6F 7F ED\n" +
  "     46 0C 7D F7  FF 41 FC 7F  17 9E 87 E9  98 52 94 58\n" +
  "     E3 78 6D F9  64 99 6D 9F  70 88 4B 9C  BC 4A 71 CC\n" +
  "     E3 EF 32 1F  BE C2 8E E1  FF C3 EB 75  D3 D6 D6 06\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     4 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     0F 4E 9F D0  68 52 58 51  F1 10 F1 8A  87 58 8B 9E\n" +
  "     62 8D F5 D6  98 25 2E 7C  13 6C 06 9B  7A 99 5F 27\n" +
  "     FE 0E C3 A6  DD CD 64 38  17 9D 5E 09  6F 97 8B 3D\n" +
  "     EB 0A 9D 8B  E2 6E 8F 0E  98 B2 C9 CB  5A AA F0 F0\n" +
  "     D0 25 FA 38  AC E8 9E 69  07 05 DF F0  03 44 28 17\n" +
  "     F7 49 6D B6  37 4F 44 CE  87 ED 29 07  35 6D 83 D6\n" +
  "     DF 2D 2C 3A  9F DF 5B 01  7C 2C B0 DA  E2 5A CB DE\n" +
  "     39 A5 58 C8  5F 64 11 83  61 7B 7B 10  D4 5D 87 20\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     5 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     83 94 B0 2E  76 4C 3A FC  A6 56 94 92  BA B4 29 29\n" +
  "     2E C2 5B 37  E4 66 AD 99  64 40 44 45  20 BC 5A 4D\n" +
  "     CF AF AA 8A  C7 68 16 5D  6E E3 31 68  63 FD 06 97\n" +
  "     FC 0F CF EA  A6 51 C9 D8  E8 6D 13 7E  9B F4 72 F7\n" +
  "     54 71 F9 D9  CA 07 BE 4E  CB 85 B2 45  DE 5E 80 5C\n" +
  "     F0 C6 11 07  98 79 62 19  A0 EC 63 41  72 05 33 B7\n" +
  "     25 2A 9B 37  57 80 F3 3C  82 33 9C A5  8B 5E E4 5A\n" +
  "     E3 84 E3 5C  FC BE 2C 94  4C E7 7A 2B  81 9B 33 F6\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     6 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     28 B2 7E A5  19 48 BC C2  4F CB 5D 52  63 08 72 0A\n" +
  "     EB 4D A0 8F  49 2A 9C 83  20 4E EF E7  DF 73 92 E9\n" +
  "     A4 11 34 12  47 E0 EA C7  9B AD 8D FC  18 19 3B 6A\n" +
  "     12 38 DE 8A  8F 7D 1A 55  7E 1F 43 53  AC 32 84 53\n" +
  "     70 C2 EB 31  21 01 82 F9  C3 DE 8C 8D  29 60 35 B4\n" +
  "     5F 71 8D E7  BB 2A F6 C3  ED 83 52 0B  0A A8 F2 10\n" +
  "     D6 52 28 AA  09 AC 30 58  53 CC 97 34  CB 7D 20 AD\n" +
  "     74 5D 54 1B  59 12 8C C1  16 8C 83 8D  2C 81 42 C2\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     7 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     76 C2 D6 D3  D2 B8 EA 41  F9 73 C8 47  C0 FA B7 73\n" +
  "     58 49 C3 25  33 85 CA 85  33 23 3C 6F  6F 54 79 59\n" +
  "     E4 AA 8D 9E  94 39 03 73  A1 10 57 4D  EB 38 F4 12\n" +
  "     6B E3 8D 76  C4 EF B6 A9  07 0B 9F CE  A4 68 FD 93\n" +
  "     B6 29 39 37  C7 7A 09 6C  17 AC EB B6  87 23 78 AD\n" +
  "     DF 11 74 4C  D1 53 CA 6F  2D 7F D0 A0  AE F5 4C BC\n" +
  "     09 D6 50 7E  45 78 40 83  7C 0E 3A 25  0B 33 19 AD\n" +
  "     85 62 4B DD  35 9B 2E BA  9C CC 2B E2  B9 8C 1F 76\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     8 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     F1 FB B5 4F  26 0D 0F B9  D4 9A 29 EE  C1 84 B2 65\n" +
  "     ED C6 63 66  8A 97 20 AA  61 66 1E 43  65 9B 3C D6\n" +
  "     97 C7 00 CE  1E 3E 53 5E  0C 69 80 12  20 B5 DA 97\n" +
  "     51 38 E7 CB  1E C8 D8 E3  01 8F 07 8A  32 CA E2 8B\n" +
  "     C1 89 35 0B  68 EE 67 78  56 23 B3 72  EF 78 11 BB\n" +
  "     06 BA 6C 67  E5 84 75 96  FB 72 F2 B5  19 94 EB 8E\n" +
  "     E0 79 B9 60  E2 28 F7 02  6E 1B FE 8C  EA 08 77 49\n" +
  "     6F 98 6F D1  3D B8 2E 13  2C C4 5F 70  BB 01 0F 27\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =     9 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     0B D5 38 5E  0E 2A 7B 6E  58 90 38 2B  D3 18 7D 2D\n" +
  "     44 C3 AB A1  71 1B 80 44  0D B8 75 2D  79 E8 5D 80\n" +
  "     B7 E1 71 71  06 8A B7 C1  D2 B0 77 A1  69 6E F7 5E\n" +
  "     42 73 9E 7E  04 9B E5 DE  24 A7 64 AF  CB 54 A8 1A\n" +
  "     D4 59 66 91  E5 43 EB 16  1D F4 6A CA  06 FA 25 C5\n" +
  "     7B 24 5F BB  C8 D7 41 B7  A9 41 E0 00  A4 8E C6 09\n" +
  "     CB 00 6A 42  B2 EE 8A 90  8B DC 0C 3F  96 07 87 FF\n" +
  "     31 EE 0C AD  74 5A 86 AF  E0 CE 0D F6  C1 50 D3 6B\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =    10 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     E6 7B B7 6E  A8 00 50 1C  BD AF 74 F1  E4 14 98 9B\n" +
  "     35 33 3F 8A  CF A2 41 F0  CA 2C 9A 82  4E D8 97 05\n" +
  "     1A E8 A5 7F  CE 19 98 30  78 10 61 0C  74 F1 2B 9D\n" +
  "     1A B6 04 03  24 88 EA 02  D8 27 A1 02  75 CE FB 7D\n" +
  "     7E DA 9E 63  AA 04 48 CE  95 36 89 F4  B7 0C D0 0D\n" +
  "     B3 94 CC 89  7B 28 B3 01  79 95 38 81  97 68 D4 C1\n" +
  "     ED 9A 29 77  5B F5 BE FB  66 F9 C2 34  96 29 25 E0\n" +
  "     0A EA 1A 16  4B AF 8C 9E  D2 A5 C7 0F  49 DE 67 34\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =    32 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     DF 05 96 E5  80 88 35 A3  E3 04 AA 27  92 3D B0 5F\n" +
  "     61 DA C5 7C  06 96 A1 D1  9A BF 18 8E  70 AA 9D BC\n" +
  "     C6 59 E9 51  0F 7C 9A 37  FB C0 25 BD  4E 5E A2 93\n" +
  "     E7 8E D7 83  8D D0 B0 88  64 E8 AD 40  DD B3 A8 80\n" +
  "     31 EB EF C2  15 72 A8 99  60 D1 91 61  07 A7 DA 7A\n" +
  "     C0 C0 67 E3  4E C4 6A 86  A2 9C A6 3F  A2 50 BD 39\n" +
  "     8E B3 2E C1  ED 0F 8A C8  32 9F 26 DA  01 8B 02 9E\n" +
  "     41 E2 E5 8D  1D FC 44 DE  81 61 5E 6C  98 7E D9 C9\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =    64 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     3C FB B7 9C  D8 8A F8 EE  09 C7 67 0B  CB AB 69 07\n" +
  "     A3 1F 80 FA  31 D9 D7 C9  D5 08 26 C9  56 8F 30 7A\n" +
  "     78 BD 25 49  61 39 8C 76  B6 E3 38 FD  9C A5 F3 51\n" +
  "     05 93 50 D3  09 63 C3 32  06 59 B2 23  B9 91 FC 46\n" +
  "     D1 30 76 86  FE 2B 47 63  D9 F5 93 C5  7A D5 AD BC\n" +
  "     45 CA F2 EA  3D C6 09 0F  5A 74 FA 5F  A6 D9 E9 83\n" +
  "     89 64 EA 0A  2A A2 16 83  1A B0 69 B0  06 29 A1 A9\n" +
  "     B0 37 08 34  03 BD B2 5D  3D 06 A2 1C  43 0C 87 DD\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   128 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     F2 BB A8 38  00 C1 1A 59  1F 21 13 8B  2B 5A 3F E1\n" +
  "     14 82 00 83  A7 92 CD 10  B9 73 51 65  93 E6 DF 4E\n" +
  "     30 4B 75 FC  C5 14 14 76  13 CA 19 83  40 61 22 15\n" +
  "     14 7F D6 56  5C 73 C7 43  08 B4 3A F8  3C 0C FF A1\n" +
  "     59 4F 81 6F  BD AA C8 F5  9D 39 9F 28  73 D7 19 C2\n" +
  "     FD 67 B0 07  54 4D B2 BB  DB AB AF 7C  98 11 48 ED\n" +
  "     AB 95 EF 94  CC 9D 3C 6E  09 CD F2 30  D3 C3 C2 F6\n" +
  "     6F 12 8D F2  E5 D1 B6 B2  6B 1A 58 FF  3B 1C BB 47\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   192 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     0A 1B 96 00  99 FC 9D 65  3B 0F D1 F5  B6 B9 72 FB\n" +
  "     36 69 07 B7  72 CB CE 5A  59 B6 17 1D  79 35 50 6F\n" +
  "     70 C2 12 BD  16 9D 68 C5  CF D8 61 83  43 61 1B 7E\n" +
  "     B2 E6 86 FF  1D C7 C0 3A  57 E1 A5 5E  D1 07 26 84\n" +
  "     81 61 EE A9  03 D5 3B 58  45 9B E4 2D  95 DF 98 9C\n" +
  "     66 C2 EE A4  E5 1C DE 27  2C 2D 8B E6  7B F3 BC A2\n" +
  "     AE E6 33 77  7E B8 48 67  81 EA A0 60  D0 F5 38 AB\n" +
  "     D6 C9 3D BD  2D 1B F6 6E  6F 50 BF DC  AC 37 25 A4\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   255 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     E1 4A 1A 89  EB 44 89 5C  BA 34 64 79  94 31 FB 90\n" +
  "     0C FC 32 2C  5F EB CB A1  66 47 37 C4  A2 C5 1D 99\n" +
  "     97 B4 4C 7F  84 60 AA DD  E2 AB 59 88  83 3A D7 F1\n" +
  "     30 B3 04 D5  67 2C E5 D9  FC 60 F1 60  39 74 06 59\n" +
  "     F5 11 61 4D  DA CF 4C 2B  1E 68 8A 7F  4E 7A 8D 95\n" +
  "     EB 1D 54 03  7B 36 13 1F  A8 44 92 7B  74 04 AD 06\n" +
  "     38 46 B3 EA  CC A7 FA CA  24 35 FD 6B  96 CD 39 9D\n" +
  "     45 F1 B0 43  42 70 85 60  0D 86 C5 B6  90 20 22 AA\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   256 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     3E 0C D7 93  8D 71 C3 9F  FB B0 8A 6B  A7 99 5A DE\n" +
  "     3A D1 40 E2  C0 C4 5C DB  AF B0 99 24  7E 08 E4 C2\n" +
  "     0B 61 C1 F8  85 CE D5 ED  2F 81 66 80  92 50 34 91\n" +
  "     82 36 E5 80  7F 0E EC F3  F2 7E 9C FC  A3 66 75 EB\n" +
  "     75 87 3E FA  1F B4 1F 17  54 1D C2 F7  C2 46 9E AE\n" +
  "     CB 35 CC 7C  A5 8E 48 98  04 CA F5 6F  09 FB 97 C9\n" +
  "     F6 89 C6 4A  D4 9C 68 88  F8 6C 48 3E  90 1B D3 D2\n" +
  "     57 98 B3 94  EF 93 FA F9  15 49 00 F9  2F 31 F4 33\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   257 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     00 D4 4B 25  83 C9 4C E0  7C 38 C9 17  B6 94 AF 50\n" +
  "     7A CB 81 9D  B5 1E 08 72  97 17 A0 6F  C4 45 E7 61\n" +
  "     27 F8 4A 4A  AE B8 7A F8  D5 17 45 3F  7B F8 44 26\n" +
  "     76 3D C9 46  CD 19 78 78  3A 80 C9 63  41 B6 00 36\n" +
  "     1D 1D 5E 9F  EF 0D 31 0A  8B C3 56 6B  66 52 F4 9E\n" +
  "     BC 89 81 F7  89 05 CA 65  C7 76 DD 45  2F C1 14 5C\n" +
  "     3C D1 2B B9  38 20 96 E4  B7 84 82 5B  5F C2 50 1E\n" +
  "     B9 0C CB A1  A6 92 E5 77  93 E1 04 3E  81 15 4C 60\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   384 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     CD FC 5F A0  A8 44 1A D1  4E 0F 27 10  68 64 E7 FF\n" +
  "     3A 24 2A AA  A5 53 D0 0E  7B 46 5F B6  DB 4A 24 B3\n" +
  "     CD 02 25 93  54 2F 48 26  C5 9B 65 A0  79 ED E3 8C\n" +
  "     A6 AC 99 AC  B1 A2 40 C4  B5 FD 3C 06  03 77 42 36\n" +
  "     95 24 29 31  2E 2E FA 77  75 75 4A 96  98 91 57 FE\n" +
  "     57 84 BD A2  54 78 88 F9  76 B2 3C BE  D7 7E 1E 27\n" +
  "     BC D7 50 AA  D4 45 44 8C  D7 EA 69 EB  94 AA 90 77\n" +
  "     45 12 33 5F  13 ED 73 AF  D4 F5 9D 01  59 0B 1C E1\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   511 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     97 36 F6 95  CE DF 2B 0B  C1 14 FA CE  A3 30 20 97\n" +
  "     93 24 2B 55  2B 74 D8 28  41 83 F8 17  5D 60 51 21\n" +
  "     6B 0C 37 DD  C8 B1 CE 7C  C5 99 18 05  84 19 AD 1B\n" +
  "     70 BF EA B9  E2 18 DC F5  28 89 1E 8C  B7 DC 61 E7\n" +
  "     B0 F2 47 42  14 26 08 EC  5A 70 0C AF  7D 62 EC 73\n" +
  "     E4 47 06 A5  73 ED C2 14  DD E3 B7 49  7A 1F 67 E2\n" +
  "     14 9A 79 B6  9C 1A A1 4F  06 39 E0 ED  FF 1C 37 72\n" +
  "     A2 74 91 CE  D1 1E 0F 02  FF C9 A0 20  87 DC B1 C4\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   512 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     72 66 75 2F  7E 9A A0 4B  D7 D8 A1 B1  60 30 67 7D\n" +
  "     E6 02 13 01  F6 A6 24 73  C7 6B AE 2B  98 BB F8 AA\n" +
  "     D7 3B D0 0A  4B 50 35 F7  41 CA F2 31  7A B8 0E 4E\n" +
  "     97 F5 C5 BB  E8 AC C0 E8  B4 24 BC B1  3C 7C 67 40\n" +
  "     A9 85 80 1F  BA 54 AD DD  E8 D4 F1 3F  69 D2 BF C9\n" +
  "     8A E1 04 D4  6A 21 11 45  21 7E 51 D5  10 EA 84 6C\n" +
  "     EC 95 81 D1  4F DA 07 9F  77 5C 8B 18  D6 6C B3 1B\n" +
  "     F7 06 09 96  EE 8A 69 EE  E7 F1 07 90  9C E5 9A 97\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   513 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     61 62 FD ED  D4 E0 D4 52  09 66 9B 1A  8A B4 A4 51\n" +
  "     DF 72 2A E7  B7 FF C1 46  C2 1B 95 A4  75 15 DE DC\n" +
  "     96 0E CE 67  19 6D 9C CC  4E 0F BA 5A  B7 E0 CC D4\n" +
  "     02 FC 8F D1  8B B8 AD B5  2C 78 4C EF  88 EE FF E5\n" +
  "     48 48 87 A5  01 FB C1 A0  6B 91 2B 0E  BD 48 B7 BD\n" +
  "     61 91 17 40  F2 C5 9B EA  71 80 93 F5  F0 C7 C8 8E\n" +
  "     C5 1D E8 3D  F0 B8 7D 1F  B5 84 42 A6  C1 9B F1 B7\n" +
  "     2F 08 28 75  97 EC EE B6  2B A3 33 C9  DA EF 97 B8\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =   768 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     71 F4 0B F2  AA 63 51 25  EF 83 C8 DF  0D 4E 9E A1\n" +
  "     8B 73 B5 6B  E4 F4 5E 89  B9 10 A7 C6  8D 39 6B 65\n" +
  "     B0 9D 18 AB  C7 D1 B6 DE  3F 53 FD 5D  E5 83 E6 F2\n" +
  "     2E 61 2D D1  7B 29 20 68  AF 60 27 DA  AF 8B 4C D6\n" +
  "     0A CF 5B C8  50 44 74 1E  9F 7A 1F 42  3F 58 27 F5\n" +
  "     E3 60 93 0A  2E 71 91 22  39 AF 9F C6  34 36 04 FD\n" +
  "     CF 3F 35 69  85 4F 2B B8  D2 5A 81 E3  B3 F5 26 1A\n" +
  "     02 FE 82 92  AA AA 50 C3  24 10 1A B2  C7 A2 F3 49\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  1023 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     2E 38 C3 60  02 64 5B 43  3A CD A2 03  4B EB 02 BB\n" +
  "     6E 10 BC 97  86 ED DD F3  96 A5 97 B6  64 FD EF EE\n" +
  "     D0 6F 9C 64  EC 1E 2E AB  71 60 C9 0F  74 E0 6B A8\n" +
  "     00 10 00 81  A7 74 93 43  65 EC EA B0  AA CA A1 FA\n" +
  "     7C 38 BF F8  27 40 E1 4A  61 22 74 E7  2A F9 DB 87\n" +
  "     51 10 7B 73  5C B0 74 C7  3D 3E BF 2C  53 A5 4D AF\n" +
  "     68 04 FF 30  F7 1C 97 FE  47 38 B6 2F  79 39 D7 83\n" +
  "     8D 31 06 3A  6E B5 D8 C0  62 B0 2C 3E  82 3B C5 F3\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  160-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     17 C3 C5 33  B2 7D 66 6D  A5 56 AE 58  6E 64 1B 7A\n" +
  "     3A 0B CC 45\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  224-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     66 25 DF 98  01 58 10 09  12 5E A4 E5  C9 4A D6 F1\n" +
  "     A2 D6 92 C2  78 82 2C CB  6E B6 72 35\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  256-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     6C 5B 67 1C  17 66 F6 EE  CE A6 D2 4B  64 1D 4A 6B\n" +
  "     F8 4B BA 13  A1 97 6F 8F  80 B3 F3 0E  E2 F9 3D E6\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  384-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     98 AF 45 4D  7F A3 70 6D  FA AF BF 58  C3 F9 94 48\n" +
  "     68 B5 7F 68  F4 93 98 73  47 A6 9F CE  19 86 5F EB\n" +
  "     BA 04 07 A1  6B 4E 82 06  50 35 65 1F  0B 1E 03 27\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  512-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     0B 50 65 8B  7F 45 EC C7  CF 21 1D 5E  2D 16 A8 AE\n" +
  "     57 64 B2 82  71 C1 36 C8  B0 3C 1C C3  08 AB AC E9\n" +
  "     EE CA FF 85  84 CC E9 7A  9A B7 58 04  B1 25 0A 30\n" +
  "     A7 6D 69 13  9B 47 A4 33  E9 FA EB E6  A4 B7 DD 10\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     21 1A C4 79  E9 96 11 41  DA 3A AC 19  D3 20 A1 DB\n" +
  "     BB FA D5 5D  2D CE 87 E6  A3 45 FC D5  8E 36 82 75\n" +
  "     97 37 84 32  B4 82 D8 9B  AD 44 DD DB  13 E6 AD 86\n" +
  "     E0 EE 1E 08  82 B4 EB 0C  D6 A1 81 E9  68 5E 18 DD\n" +
  "     30 2E BB 3A  A7 45 02 C0  62 54 DC AD  FB 2B D4 5D\n" +
  "     28 8F 82 36  6B 7A FC 3B  C0 F6 B1 A3  C2 E8 F8 4D\n" +
  "     37 FB ED D0  7A 3F 8F CF  F8 4F AF 24  C5 3C 11 DA\n" +
  "     60 0A AA 11  8E 76 CF DC  B3 66 D0 B3  F7 72 9D CE\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  264-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     DC 1D 25 3B  7C AD BD AE  F1 85 03 B1  80 9A 7F 1D\n" +
  "     4F 8C 32 3B  7F 6F 8C A5  0B 76 D3 86  46 49 CE 1C\n" +
  "     7D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024:  520-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     DE CD 79 57  8D 12 BF 68  06 53 0C 38  22 30 A2 C7\n" +
  "     83 64 29 C7  0C AC 94 11  79 E1 DD 98  29 38 BA B9\n" +
  "     1F B6 F3 63  8D F1 CC 1E  F6 15 EC FC  42 49 E5 AC\n" +
  "     A8 A7 3C 4C  1E EB EF 66  2A 83 6D 0B  E9 03 B0 01\n" +
  "     46\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1032-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     44 0F E6 91  E0 4F 1F ED  8C 25 3D 6C  46 70 64 61\n" +
  "     56 F3 3F FF  AE A7 02 DE  94 45 DF 57  39 EB 96 0C\n" +
  "     EC F8 5D 56  E2 E6 86 0A  61 02 11 A5  C9 09 93 2A\n" +
  "     B7 74 B9 78  AA 0B 0D 5B  BC E8 27 75  17 2A B1 2D\n" +
  "     CE DD D5 1D  1E B0 30 05  7C E6 1B EA  6C 18 F6 BB\n" +
  "     36 8D 26 AE  76 A9 E4 4A  96 2E B1 32  E6 C4 2C 25\n" +
  "     D9 FE CC 4F  13 34 83 00  CA 55 C7 8E  09 90 DE 96\n" +
  "     C1 AE 24 EB  3E E3 32 47  82 C9 3D D6  28 26 0A 2C\n" +
  "     8D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 2056-bit hash, msgLen =  1024 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "MAC key =    0 bytes:\n" +
  "    (none)          /* use InitExt() call */\n" +
  "Result:\n" +
  "     17 30 BD 2F  EB D5 90 95  C8 01 A4 37  60 58 DD 04\n" +
  "     77 14 52 50  6F 3E BF 8F  22 CE 86 61  D2 BD 7E 16\n" +
  "     17 CC 9C C8  81 33 C4 D8  CC 22 F4 C2  0F 09 B8 8E\n" +
  "     64 30 48 E0  64 CE 19 3D  08 8C 4C D8  BE AD 28 92\n" +
  "     0E 08 5B E8  5E DF E9 1D  A7 54 F0 AB  4A 4A 35 AA\n" +
  "     D8 28 52 35  31 C5 96 C1  2C 2A 5A A8  23 57 35 71\n" +
  "     3A CD 61 77  76 00 6E 0A  9E 8B EC 14  2F 49 FA 59\n" +
  "     EE C7 53 BB  5F EA 3C 8D  9F D5 B1 B8  C1 D9 3F 7D\n" +
  "     04 0D 24 17  D3 A3 77 8F  75 06 74 D4  38 E1 B5 0C\n" +
  "     01 4C 96 85  61 86 1C 79  F4 2B BC 60  C2 3C 83 54\n" +
  "     13 A5 9C E3  8A 2D 81 DE  03 8B 44 85  1D 5E 8C 37\n" +
  "     47 BA E1 4C  D3 D8 D4 AD  46 3C 79 69  41 FA 54 C6\n" +
  "     D9 65 30 84  67 A5 AA 08  64 DA 95 9F  D6 DC 17 F9\n" +
  "     94 4E 35 9E  41 5B 72 F7  FA 31 E4 05  30 F1 65 02\n" +
  "     24 1A A5 2B  1C 83 F5 41  7E C8 D9 B2  08 98 63 EA\n" +
  "     3E EE D1 72  04 6B 32 8E  EC 17 6F 1E  13 3F 13 4C\n" +
  "     A5\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  1025 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69\n" +
  "MAC key =   64 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "Result:\n" +
  "     4B 65 27 2F  B7 49 FC 39  2D 33 D9 22  15 21 62 21\n" +
  "     C0 0B 3A FF  19 58 09 A1  26 D3 4E AA  09 BD 94 D5\n" +
  "     D5 9D 3C 39  7F FF 08 A2  BC 6B 72 94  68 AE 0A F7\n" +
  "     69 4A AB 96  96 E0 9A 96  2C A5 D4 EE  DE 14 64 7C\n" +
  "     17 9A 26 BB  19 38 CA D3  7D 49 37 15  25 5D 87 24\n" +
  "     5E 86 97 F2  D8 B0 6C 29  F9 7C 56 68  ED 51 9D D5\n" +
  "     0F 9B 36 9C  DA 14 B8 04  32 FE EA 63  CD B0 81 1F\n" +
  "     29 B2 EA 2B  49 63 61 77  4E DE 43 04  18 5B B8 3D\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  2047 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =  128 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "Result:\n" +
  "     99 6E 53 41  9B C4 D9 47  47 CE 63 07  13 53 F5 46\n" +
  "     6A CB C4 14  81 F3 5C 69  8D EB DB 9B  AF F4 19 88\n" +
  "     13 0E 80 96  09 4A 44 05  06 99 84 A5  49 35 1E 61\n" +
  "     D6 AF EC 4C  CD 76 6D 77  6C 28 6B CA  14 ED 31 6A\n" +
  "     94 9E 73 6C  91 07 89 40  1C 1F 84 0E  21 31 28 1D\n" +
  "     C5 12 CF DB  7A 6A 8A AD  02 87 57 80  EA 30 6D DD\n" +
  "     14 1F E8 5A  4F BC BF B0  CE C6 00 6D  E4 C8 3F E7\n" +
  "     A5 61 37 6F  4A 2F 16 0F  F9 A6 CA 37  06 B7 F4 84\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  2048 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "MAC key =  129 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C\n" +
  "Result:\n" +
  "     46 A4 2B 0D  7B 86 79 F8  FC EA 15 6C  07 2C F9 83\n" +
  "     3C 46 8A 7D  59 AC 5E 5D  32 69 57 D6  0D FE 1C DF\n" +
  "     B2 7E B5 4C  76 0B 9E 04  9F DA 47 F0  B8 47 AC 68\n" +
  "     D6 B3 40 C0  2C 39 D4 A1  8C 1B DF EC  E3 F4 05 FA\n" +
  "     E8 AA 84 8B  DB EF E3 A4  C2 77 A0 95  E9 21 22 86\n" +
  "     18 D3 BE 8B  D1 99 9A 07  16 82 81 0D  E7 48 44 0A\n" +
  "     D4 16 A9 77  42 CC 9E 8A  9B 85 45 5B  1D 76 47 2C\n" +
  "     F5 62 F5 25  11 66 98 D5  CD 0A 35 DD  F8 6E 7F 8A\n" +
  "--------------------------------\n" +
  "\n" +
  ":Skein-1024: 1024-bit hash, msgLen =  2049 bits, data = 'random+MAC'\n" +
  "\n" +
  "Message data:\n" +
  "     D3 09 0C 72  16 75 17 F7  C7 AD 82 A7  0C 2F D3 F6\n" +
  "     44 3F 60 83  01 59 1E 59  8E AD B1 95  E8 35 71 35\n" +
  "     BA 26 FE DE  2E E1 87 41  7F 81 60 48  D0 0F C2 35\n" +
  "     12 73 7A 21  13 70 9A 77  E4 17 0C 49  A9 4B 7F DF\n" +
  "     F4 5F F5 79  A7 22 87 74  31 02 E7 76  6C 35 CA 5A\n" +
  "     BC 5D FE 2F  63 A1 E7 26  CE 5F BD 29  26 DB 03 A2\n" +
  "     DD 18 B0 3F  C1 50 8A 9A  AC 45 EB 36  24 40 20 3A\n" +
  "     32 3E 09 ED  EE 63 24 EE  2E 37 B4 43  2C 18 67 ED\n" +
  "     69 6E 6C 9D  B1 E6 AB EA  02 62 88 95  4A 9C 2D 57\n" +
  "     58 D7 C5 DB  7C 9E 48 AA  3D 21 CA E3  D9 77 A7 C3\n" +
  "     92 60 66 AA  39 3D BD 53  8D D0 C3 0D  A8 91 6C 87\n" +
  "     57 F2 4C 18  48 80 14 66  8A 26 27 16  3A 37 B2 61\n" +
  "     83 3D C2 F8  C3 C5 6B 1B  2E 0B E2 1F  D3 FB DB 50\n" +
  "     7B 29 50 B7  7A 6C C0 2E  FB 39 3E 57  41 93 83 A9\n" +
  "     20 76 7B CA  2C 97 21 07  AA 61 38 45  42 D4 7C BF\n" +
  "     B8 2C FE 5C  41 53 89 D1  B0 A2 D7 4E  2C 5D A8 51\n" +
  "     FD\n" +
  "MAC key =  257 bytes:\n" +
  "     CB 41 F1 70  6C DE 09 65  12 03 C2 D0  EF BA DD F8\n" +
  "     47 A0 D3 15  CB 2E 53 FF  8B AC 41 DA  00 02 67 2E\n" +
  "     92 02 44 C6  6E 02 D5 F0  DA D3 E9 4C  42 BB 65 F0\n" +
  "     D1 41 57 DE  CF 41 05 EF  56 09 D5 B0  98 44 57 C1\n" +
  "     93 5D F3 06  1F F0 6E 9F  20 41 92 BA  11 E5 BB 2C\n" +
  "     AC 04 30 C1  C3 70 CB 3D  11 3F EA 5E  C1 02 1E B8\n" +
  "     75 E5 94 6D  7A 96 AC 69  A1 62 6C 62  06 B7 25 27\n" +
  "     36 F2 42 53  C9 EE 9B 85  EB 85 2D FC  81 46 31 34\n" +
  "     6C 04 2E B4  18 7A A1 C0  15 A4 76 70  32 C0 BB 28\n" +
  "     F0 76 B6 64  85 F5 15 31  C1 2E 94 8F  47 DB C2 CB\n" +
  "     90 4A 4B 75  D1 E8 A6 D9  31 DA B4 A0  7E 0A 54 D1\n" +
  "     BB 5B 55 E6  02 14 17 46  BD 09 FB 15  E8 F0 1A 8D\n" +
  "     74 E9 E6 39  59 CB 37 33  6B C1 B8 96  EC 78 DA 73\n" +
  "     4C 15 E3 62  DB 04 36 8F  BB A2 80 F2  0A 04 3E 0D\n" +
  "     09 41 E9 F5  19 3E 1B 36  0A 33 C4 3B  26 65 24 88\n" +
  "     01 25 22 2E  64 8F 05 F2  8B E3 4B A3  CA BF C9 C5\n" +
  "     44\n" +
  "Result:\n" +
  "     ED 9D C9 D7  0C 14 9D 79  64 4D B4 53  D8 AA A5 B0\n" +
  "     22 9B 4E F9  3D A3 7F 26  8C 14 35 0D  6C 2A 42 F5\n" +
  "     EA DC FC 10  A9 47 BE C9  7A C5 05 76  0C DA 75 0A\n" +
  "     7E EC D9 C9  00 24 73 B9  8F B1 CE F7  0E 4D 68 24\n" +
  "     FA 8F CF A3  20 6D 30 EE  B4 2A 29 D4  63 89 FE B5\n" +
  "     89 E8 E0 51  A5 6F AE 2E  74 1D F0 8C  17 A4 12 C2\n" +
  "     97 5C DB BF  8A 4D 7B BE  39 2A 38 22  57 8E 56 D0\n" +
  "     27 69 CF 73  F4 14 54 99  74 77 C9 50  C9 12 73 15\n" +
  "--------------------------------";














