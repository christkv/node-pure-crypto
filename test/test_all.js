require.paths.unshift("./lib", "./external-libs/node-async-testing", "./test");

// Tests
require('aes_test').suite.runTests(function() {});

