require.paths.unshift("./lib", "./lib/prng", "./lib/symmetric", "./external-libs/node-async-testing", "./test");

// Tests
require('aes_test').suite.runTests(function() {});
require('cbc_test').suite.runTests(function() {});
require('ofb_test').suite.runTests(function() {});
require('cfb8_test').suite.runTests(function() {});
require('cfb_test').suite.runTests(function() {});
require('ecb_test').suite.runTests(function() {});
require('blowfish_test').suite.runTests(function() {});
require('des_test').suite.runTests(function() {});
require('triple_des_test').suite.runTests(function() {});
require('rabbit_test').suite.runTests(function() {});

