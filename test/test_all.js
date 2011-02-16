require.paths.unshift("./lib", "./external-libs/node-async-testing", "./test");

// Tests
require('aes_test').suite.runTests(function() {});
require('cbc_test').suite.runTests(function() {});
require('ofb_test').suite.runTests(function() {});

