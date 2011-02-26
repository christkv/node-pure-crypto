require.paths.unshift("./lib", "./lib/prng", "./lib/symmetric", "./external-libs/node-async-testing", "./test");

// Debug stuff
var debug = require('sys').debug,
  inspect = require('sys').inspect;

// Tests
require('aes_test').suite.runTests(function() {});
// Set max emitters (bug if no emitters registered)
debug(inspect(process.setMaxListeners(100)))
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

