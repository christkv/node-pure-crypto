require.paths.unshift("./lib", "./external-libs/node-async-testing");

var TestSuite = require('async_testing').TestSuite,
  debug = require('sys').debug,
  inspect = require('sys').inspect,
  AESKey = require('aes').AESKey,
  XTeaKey = require('xtea').XTeaKey,
  CBCMode = require('cbc').CBCMode,
  NullPad = require('padding').NullPad,
  crypto = require('crypto'),
  BinaryParser = require('binary_parser').BinaryParser;
    
var suite = exports.suite = new TestSuite("CBCMode Test");

var hexStringToBinaryArray = function(string) {
  var numberofValues = string.length / 2;
  var array = new Array(numberofValues);

  for(var i = 0; i < numberofValues; i++) {
    array[i] = parseInt(string[i*2] + string[i*2 + 1], 16);
  }
  
  return array;
}

var toHex = function(array) {
  var s = "";
  for(var i = 0; i < array.length; i++) {
    var v = array[i].toString(16);
    if(v.length == 1) v = "0" + v; 
    s += v.toUpperCase();
  }
  return s;
}

suite.addTests({  
  "testCBC_AES128":function(assert, finished) {
    var key = hexStringToBinaryArray("2b7e151628aed2a6abf7158809cf4f3c");
    var pt = hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = hexStringToBinaryArray(
      "7649abac8119b246cee98e9b12e9197d" + 
			"5086cb9b507219ee95db113a917678b2" + 
			"73bed6b8e3c1743b7116e69e22229516" + 
			"3ff1caa1681fac09120eca307586e1a7");
		
		var iv = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
		var cbc = new CBCMode(new AESKey(key), new NullPad(), iv);
		var src = cbc.encrypt(pt);
    assert.deepEqual(ct, src);

    var decrypt = cbc.decrypt(src);    
    assert.deepEqual(pt, decrypt);
    finished();
  },
  
  "test_CBC_AES192":function(assert, finished) {
    var key = hexStringToBinaryArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    var pt = hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = hexStringToBinaryArray(
			"4f021db243bc633d7178183a9fa071e8" + 
			"b4d9ada9ad7dedf4e5e738763f69145a" + 
			"571b242012fb7ae07fa9baac3df102e0" + 
			"08b0e27988598881d920a9e64f5615cd");

		var iv = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
		var cbc = new CBCMode(new AESKey(key), new NullPad(), iv);
		var src = cbc.encrypt(pt);
    assert.deepEqual(ct, src);

    var decrypt = cbc.decrypt(src);    
    assert.deepEqual(pt, decrypt);    
    finished();
  },
  
  "test_CBC_AES256":function(assert, finished) {
    var key = hexStringToBinaryArray(
      "603deb1015ca71be2b73aef0857d7781" + 
			"1f352c073b6108d72d9810a30914dff4");			
    var pt = hexStringToBinaryArray(
			"6bc1bee22e409f96e93d7e117393172a" + 
			"ae2d8a571e03ac9c9eb76fac45af8e51" + 
			"30c81c46a35ce411e5fbc1191a0a52ef" + 
			"f69f2445df4f9b17ad2b417be66c3710");
    var ct = hexStringToBinaryArray(
			"f58c4c04d6e5f1ba779eabfb5f7bfbd6" + 
			"9cfc4e967edb808d679f777bc6702c7d" + 
			"39f23369a9d9bacfa530e26304231461" + 
			"b2eb05e2c39be9fcda6c19078c6a9d1b");

		var iv = hexStringToBinaryArray("000102030405060708090a0b0c0d0e0f");
		var cbc = new CBCMode(new AESKey(key), new NullPad(), iv);
		var src = cbc.encrypt(pt);
    assert.deepEqual(ct, src);

    var decrypt = cbc.decrypt(src);    
    assert.deepEqual(pt, decrypt);    
    finished();
  },  
  
  "testAES":function(assert, finished) {
		var keys = [
  		"00010203050607080A0B0C0D0F101112",
  		"14151617191A1B1C1E1F202123242526"];
		var cts = [
  		"D8F532538289EF7D06B506A4FD5BE9C94894C5508A8D8E29AB600DB0261F0555A8FA287B89E65C0973F1F8283E70C72863FE1C8F1F782084CE05626E961A67B3",
  		"59AB30F4D4EE6E4FF9907EF65B1FB68C96890CE217689B1BE0C93ED51CF21BB5A0101A8C30714EC4F52DBC9C6F4126067D363F67ABE58463005E679B68F0B496"];
		var pts = [
  		"506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359506812A45F08C889B97F5980038B8359",
  		"5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B5C6D71CA30DE8B8B00549984D2EC7D4B"];
  		
  	for(var i = 0; i < keys.length; i++) {
  	  var key = hexStringToBinaryArray(keys[i]);
  	  var pt = hexStringToBinaryArray(pts[i]);
  	  var ct = hexStringToBinaryArray(cts[i]);
  	  var aes = new AESKey(key);
  		var iv = hexStringToBinaryArray("00000000000000000000000000000000");
  	  var cbc = new CBCMode(aes, null, iv);
  	  // Encrypt the pt key
  	  var encrypted = cbc.encrypt(pt);
  	  assert.deepEqual(ct, encrypted);
  	  // Decrypt
  	  var decrypted = cbc.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
  	  finished();
  	}
  },
  
  "testXTea":function(assert, finished) {
		var keys = [
		  "2b02056806144976775d0e266c287843",
  		"00000000000000000000000000000000"];
		var cts = [
		  "790958213819878370eb8251ffdac371081c5a457fc42502c63910306fea150be8674c3b8e675516",
  		"2dc7e8d3695b0538d8f1640d46dca717790af2ab545e11f3b08e798eb3f17b1744299d4d20b534aa"];
		var pts = [
		  "74657374206d652e74657374206d652e74657374206d652e74657374206d652e",
  		"0000000000000000000000000000000000000000000000000000000000000000"];

  	for(var i = 0; i < keys.length; i++) {
  	  var key = hexStringToBinaryArray(keys[i]);
  	  var pt = hexStringToBinaryArray(pts[i]);
  	  var ct = hexStringToBinaryArray(cts[i]);
  	  var tea = new XTeaKey(key);
  		var iv = hexStringToBinaryArray("00000000000000000000000000000000");
  	  var cbc = new CBCMode(tea, null, iv);
  	  // Encrypt the pt key
  	  var encrypted = cbc.encrypt(pt);
  	  assert.deepEqual(ct, encrypted);
  	  // Decrypt
      var decrypted = cbc.decrypt(encrypted);
      assert.deepEqual(pt, decrypted);
  	  finished();
  	}    
  },
});
