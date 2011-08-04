require.paths.unshift("./lib");

var TestSuite = testCase = require('../../../deps/nodeunit').testCase,
  debug = require('util').debug
  inspect = require('util').inspect,
  nodeunit = require('../../../deps/nodeunit'),
  crypto = require('crypto'),
  BlowFish = require('symmetric/block/blowfish').BlowFish,
  util = require('utils');
    
var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
}

module.exports = testCase({
  setUp: function(callback) {
    callback();        
  },
  
  tearDown: function(callback) {
    callback();        
  },

  "BlowFish ECB Test Vectors":function(test) {
    var keys = ["0000000000000000", "FFFFFFFFFFFFFFFF", "3000000000000000", "1111111111111111", "0123456789ABCDEF", 
      "1111111111111111", "0000000000000000", "FEDCBA9876543210", "7CA110454A1A6E57", "0131D9619DC1376E", 
      "07A1133E4A0B2686", "3849674C2602319E", "04B915BA43FEB5B6", "0113B970FD34F2CE", "0170F175468FB5E6", 
      "43297FAD38E373FE", "07A7137045DA2A16", "04689104C2FD3B2F", "37D06BB516CB7546", "1F08260D1AC2465E", 
      "584023641ABA6176", "025816164629B007", "49793EBC79B3258F", "4FB05E1515AB73A7", "49E95D6D4CA229BF", 
      "018310DC409B26D6", "1C587F1C13924FEF", "0101010101010101", "1F1F1F1F0E0E0E0E", "E0FEE0FEF1FEF1FE", 
      "0000000000000000", "FFFFFFFFFFFFFFFF", "0123456789ABCDEF", "FEDCBA9876543210" ];
    var pts = ["0000000000000000", "FFFFFFFFFFFFFFFF", "1000000000000001", "1111111111111111", "1111111111111111", 
      "0123456789ABCDEF", "0000000000000000", "0123456789ABCDEF", "01A1D6D039776742", "5CD54CA83DEF57DA", 
      "0248D43806F67172", "51454B582DDF440A", "42FD443059577FA2", "059B5E0851CF143A", "0756D8E0774761D2", 
      "762514B829BF486A", "3BDD119049372802", "26955F6835AF609A", "164D5E404F275232", "6B056E18759F5CCA", 
      "004BD6EF09176062", "480D39006EE762F2", "437540C8698F3CFA", "072D43A077075292", "02FE55778117F12A", 
      "1D9D5C5018F728C2", "305532286D6F295A", "0123456789ABCDEF", "0123456789ABCDEF", "0123456789ABCDEF", 
      "FFFFFFFFFFFFFFFF", "0000000000000000", "0000000000000000", "FFFFFFFFFFFFFFFF" ];
    var cts = ["4EF997456198DD78", "51866FD5B85ECB8A", "7D856F9A613063F2", "2466DD878B963C9D", "61F9C3802281B096", 
      "7D0CC630AFDA1EC7", "4EF997456198DD78", "0ACEAB0FC6A0A28D", "59C68245EB05282B", "B1B8CC0B250F09A0", 
      "1730E5778BEA1DA4", "A25E7856CF2651EB", "353882B109CE8F1A", "48F4D0884C379918", "432193B78951FC98", 
      "13F04154D69D1AE5", "2EEDDA93FFD39C79", "D887E0393C2DA6E3", "5F99D04F5B163969", "4A057A3B24D3977B", 
      "452031C1E4FADA8E", "7555AE39F59B87BD", "53C55F9CB49FC019", "7A8E7BFA937E89A3", "CF9C5D7A4986ADB5", 
      "D1ABB290658BC778", "55CB3774D13EF201", "FA34EC4847B268B2", "A790795108EA3CAE", "C39E072D9FAC631D", 
      "014933E0CDAFF6E4", "F21E9A77B71C49BC", "245946885754369A", "6B5C5A9C5D9E0A5A" ];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var data = hexStringToBinaryArray(pts[i]);      
      var ct = util.hexStringToBinaryArray(cts[i]);

      // Encrypt data
      var bf = new BlowFish();
      bf.init(true, key);
      test.equal(8, bf.processBlock(data, 0, data, 0));  // Destructive to save memory      
      test.deepEqual(ct, data);
      
      // Initialize cipher for decryption
      bf.init(false, key);
      // Decrypt the encrypted data and compare
      test.equal(8, bf.processBlock(data, 0, data, 0));
      // Check valid decrypted data
      test.deepEqual(hexStringToBinaryArray(pts[i]), data);
    }

    test.done();
  },  
  
  // "Node Compatibility Tests":function(test) {
  //   var key = "018310DC409B26D6018310DC409B26D6";
  //   var pt =  "6bc1bee22e409f96";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  // 
  //   // OFB Mode
  //   var cipher = crypto.createCipheriv("bf-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("bf-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new OFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  // 
  //   var ofb = new OFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  // 
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CBC Mode
  //   var cipher = crypto.createCipheriv("bf-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("bf-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  // 
  //   var ofb = new CBCMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  // 
  //   var ofb = new CBCMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  // 
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  // 
  //   // ECB Mode
  //   var cipher = crypto.createCipheriv("bf-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("bf-ecb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  //   
  //   var ofb = new ECBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  //   test.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  //   
  //   var ofb = new ECBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  // 
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   
  //   // CFB Mode
  //   var cipher = crypto.createCipheriv("bf-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decipher = crypto.createDecipheriv("bf-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
  //   nodeEncrypted += cipher.final('binary');
  // 
  //   var ofb = new CFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
  // 
  //   var ofb = new CFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  //   var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
  //   var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
  //   decryptedNode += decipher.final('binary');      
  // 
  //   test.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
  //   test.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
  //   test.done();    
  // },
  // 
  // "Streaming api test":function(test) {
  //   var key = "018310DC409B26D6018310DC409B26D6";
  //   // Encrypt using the pure js library    
  //   var iv = "0001020304050607";
  //   // 5K of random data
  //   var data = randomdata(1025);
  //   // Blocksize
  //   var blockSize = 32;
  //   // Encrypt using the purejs librarie's streaming api in 1024 blocks
  //   var ofb = new OFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  // 
  //   // Split the data
  //   var numberOfBlocks = Math.floor(data.length / blockSize);
  //   var leftOverbytes = data.length % blockSize;
  //   var encryptedData = "";
  // 
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
  //   }    
  // 
  //   // If we have leftover bytes
  //   if(leftOverbytes > 0) {
  //     encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
  //   }
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   encryptedData += ofb.finalEncrypt();
  // 
  //   // Encrypt using node.js to ensure have have the same
  //   var cipher = crypto.createCipheriv("bf-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
  //   var nodejsEncrypted = cipher.update(data, 'binary');
  //   nodejsEncrypted += cipher.final('binary');
  //   
  //   // Verify encrypted streaming data
  //   var a = util.binaryStringToArray(nodejsEncrypted);    
  //   var b = util.binaryStringToArray(encryptedData);    
  //   test.deepEqual(b, a);
  // 
  //   // Decrypt the streaming data
  //   var decipher = crypto.createDecipheriv("bf-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
  //   var decryptedNode = decipher.update(encryptedData, 'binary');
  //   decryptedNode += decipher.final('binary');    
  //   // Decrypted content check for node.js
  //   test.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
  //     
  //   // Clean cbc instance
  //   ofb = new OFBMode(new BlowFish(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
  //   // Split the data
  //   var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
  //   var leftOverbytes = nodejsEncrypted.length % blockSize;
  //   var decryptedData = "";
  //     
  //   for(var i = 0; i < numberOfBlocks; i++) {
  //     decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
  //   }    
  //   
  //   // Update with leftover bytes
  //   if(leftOverbytes > 0) 
  //     decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
  //     
  //   // ok dokey let's finialize (ensuring we have the last padded block added)    
  //   decryptedData += ofb.finalDecrypt();
  //     
  //   // Verify encryption
  //   var a = util.binaryStringToArray(decryptedNode);    
  //   var b = util.binaryStringToArray(decryptedData);    
  //   // Verify the decryption against node.js
  //   test.deepEqual(b, a);    
  //   test.done();
  // },  
});


















