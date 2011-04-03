require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  crypto = require('crypto'),
  TripleDESKey = require('block/triple_des').TripleDESKey,
  OFBMode = require('block/ofb').OFBMode,
  CBCMode = require('block/cbc').CBCMode,
  ECBMode = require('block/ecb').ECBMode,
  CFBMode = require('block/cfb').CFBMode,
  util = require('utils');
    
var suite = exports.suite = new TestSuite("TripleDESKey Test");

var randomdata = function(size) {
  // 5KB of random, dummy data
  var data = [];
  for (var i = 0; i < size; i++) data.push(String.fromCharCode(Math.floor(Math.random() * 256)));
  return data.join("");  
}

suite.addTests({  
  "Triple DES ECB Test Vectors":function(assert, finished) {
		var keys = [
		  "010101010101010101010101010101010101010101010101",
      "dd24b3aafcc69278d650dad234956b01e371384619492ac4",
		];
		var pts = [
  		"8000000000000000",
      "F36B21045A030303",
		];
		var cts = [
  		"95F8A5E5DD31D900",
      "E823A43DEEA4D0A4",
		];
    
    for(var i = 0; i < keys.length; i++) {
      var key = util.hexStringToBinaryArray(keys[i]);
      var pt = util.hexStringToBinaryArray(pts[i]);
      var ct = util.hexStringToBinaryArray(cts[i]);
      var des = new TripleDESKey(key);
      
      // Encryp the content
      var encrypted = des.encrypt(pt);
      assert.deepEqual(ct, encrypted);
      // Decrypt
      var decrypted = des.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
    }
    
    finished();
  },  
  
  "Node Compatibility Tests":function(assert, finished) {
    var key = "dd24b3aafcc69278d650dad234956b01e371384619492ac4";
    var pt =  "6bc1bee22e409f96";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
  
    // OFB Mode
    var cipher = crypto.createCipheriv("des-ede3-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("des-ede3-ofb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
    
    var ofb = new OFBMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
  
    var ofb = new OFBMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
  
    assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    
    // CBC Mode
    var cipher = crypto.createCipheriv("des-ede3-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("des-ede3-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
      
    var ofb = new CBCMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
    assert.deepEqual(util.binaryStringToArray(nodeEncrypted), src);
      
    var ofb = new CBCMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
      
    assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
      
    // CFB Mode
    var cipher = crypto.createCipheriv("des-ede3-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decipher = crypto.createDecipheriv("des-ede3-cfb", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var nodeEncrypted = cipher.update(util.hexStringToBinary(pt), 'binary');
    nodeEncrypted += cipher.final('binary');
      
    var ofb = new CFBMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var src = ofb.encrypt(util.hexStringToBinaryArray(pt));
      
    var ofb = new CFBMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
    var decryptedPureJs = ofb.decrypt(util.binaryStringToArray(nodeEncrypted));
    var decryptedNode = decipher.update(util.arrayToBinaryString(src), 'binary');
    decryptedNode += decipher.final('binary');      
      
    assert.deepEqual(util.binaryStringToArray(decryptedNode), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), decryptedPureJs);
    assert.deepEqual(util.hexStringToBinaryArray(pt), util.binaryStringToArray(decryptedNode));
    finished();    
  },
  
  "Streaming api test":function(assert, finished) {
    var key = "dd24b3aafcc69278d650dad234956b01e371384619492ac4";
    // Encrypt using the pure js library    
    var iv = "0001020304050607";
    // 5K of random data
    var data = randomdata(33);
    // Blocksize
    var blockSize = 32;
    // Encrypt using the purejs librarie's streaming api in 1024 blocks
    var ofb = new CBCMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));
  
    // Split the data
    var numberOfBlocks = Math.floor(data.length / blockSize);
    var leftOverbytes = data.length % blockSize;
    var encryptedData = "";
  
    for(var i = 0; i < numberOfBlocks; i++) {
      encryptedData += ofb.updateEncrypt(data.substr(i * blockSize, blockSize));
    }    
  
    // If we have leftover bytes
    if(leftOverbytes > 0) {
      encryptedData += ofb.updateEncrypt(data.substr(data.length - leftOverbytes));      
    }
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    encryptedData += ofb.finalEncrypt();
  
    // Encrypt using node.js to ensure have have the same
    var cipher = crypto.createCipheriv("des-ede3-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));    
    var nodejsEncrypted = cipher.update(data, 'binary');
    nodejsEncrypted += cipher.final('binary');
    
    // Verify encrypted streaming data
    var a = util.binaryStringToArray(nodejsEncrypted);    
    var b = util.binaryStringToArray(encryptedData);    
    assert.deepEqual(b, a);
  
    // Decrypt the streaming data
    var decipher = crypto.createDecipheriv("des-ede3-cbc", util.hexStringToBinary(key), util.hexStringToBinary(iv));
    var decryptedNode = decipher.update(encryptedData, 'binary');
    decryptedNode += decipher.final('binary');    
    // Decrypted content check for node.js
    assert.deepEqual(util.binaryStringToArray(data), util.binaryStringToArray(decryptedNode));    
      
    // Clean cbc instance
    ofb = new CBCMode(new TripleDESKey(util.hexStringToBinaryArray(key)), null, util.hexStringToBinaryArray(iv));    
    // Split the data
    var numberOfBlocks = Math.floor(nodejsEncrypted.length / blockSize);
    var leftOverbytes = nodejsEncrypted.length % blockSize;
    var decryptedData = "";
      
    for(var i = 0; i < numberOfBlocks; i++) {
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(i * blockSize, blockSize));
    }    
    
    // Update with leftover bytes
    if(leftOverbytes > 0) 
      decryptedData += ofb.updateDecrypt(nodejsEncrypted.substr(numberOfBlocks*blockSize));          
      
    // ok dokey let's finialize (ensuring we have the last padded block added)    
    decryptedData += ofb.finalDecrypt();
      
    // Verify encryption
    var a = util.binaryStringToArray(decryptedNode);    
    var b = util.binaryStringToArray(decryptedData);    
    // Verify the decryption against node.js
    assert.deepEqual(b, a);    
    finished();
  },  
});


















