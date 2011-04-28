require.paths.unshift("./lib", "./lib/prng", "./lib/symmetric", "./external-libs/node-async-testing", "./test");

// Debug stuff
var debug = require('sys').debug,
  inspect = require('sys').inspect;

// Tests
require('aes_test').suite.runTests(function() {});
// Set max emitters (bug if no emitters registered)
process.setMaxListeners(100);
// Execute rest of tests
require('cbc_test').suite.runTests(function() {});
require('ofb_test').suite.runTests(function() {});
require('cfb8_test').suite.runTests(function() {});
require('cfb_test').suite.runTests(function() {});
require('ecb_test').suite.runTests(function() {});
require('blowfish_test').suite.runTests(function() {});
require('des_test').suite.runTests(function() {});
require('triple_des_test').suite.runTests(function() {});
require('rabbit_test').suite.runTests(function() {});
require('marc4_test').suite.runTests(function() {});
require('arc4_test').suite.runTests(function() {});
require('cast_128_test').suite.runTests(function() {});
require('cast_256_test').suite.runTests(function() {});
require('rc6_test').suite.runTests(function() {});
require('rc5_test').suite.runTests(function() {});
require('idea_test').suite.runTests(function() {});
require('seed_test').suite.runTests(function() {});
require('mars_test').suite.runTests(function() {});
require('serpent_test').suite.runTests(function() {});
require('twofish_test').suite.runTests(function() {});
require('salsa20_test').suite.runTests(function() {});
require('xsalsa20_test').suite.runTests(function() {});
require('sosemanuk_test').suite.runTests(function() {});
require('hc128_test').suite.runTests(function() {});
require('hc256_test').suite.runTests(function() {});
require('vmpc_test').suite.runTests(function() {});
require('vmpcksa3_test').suite.runTests(function() {});
require('isaac_test').suite.runTests(function() {});
require('grainv1_test').suite.runTests(function() {});
require('grain128_test').suite.runTests(function() {});
require('skipjack_test').suite.runTests(function() {});
require('noekeon_test').suite.runTests(function() {});
require('gost28147_test').suite.runTests(function() {});
require('camellia_test').suite.runTests(function() {});
require('aesfast_test').suite.runTests(function() {});
require('treefish_test').suite.runTests(function() {});

// Hash functions
require('md5_test').suite.runTests(function() {});
require('md2_test').suite.runTests(function() {});
require('md4_test').suite.runTests(function() {});
require('sha1_test').suite.runTests(function() {});
require('sha224_test').suite.runTests(function() {});
require('sha256_test').suite.runTests(function() {});
require('sha384_test').suite.runTests(function() {});
require('sha512_test').suite.runTests(function() {});
require('ripemd128_test').suite.runTests(function() {});
require('ripemd160_test').suite.runTests(function() {});
require('ripemd256_test').suite.runTests(function() {});
require('ripemd320_test').suite.runTests(function() {});
require('tiger_test').suite.runTests(function() {});
require('whirlpool_test').suite.runTests(function() {});
require('skein_test').suite.runTests(function() {});
require('gost3411_test').suite.runTests(function() {});

// Mac functions
require('skeinmac_test').suite.runTests(function() {});
require('cbcblockciphermac_test').suite.runTests(function() {});
require('cfbblockciphermac_test').suite.runTests(function() {});
// require('hmac_test').suite.runTests(function() {});













