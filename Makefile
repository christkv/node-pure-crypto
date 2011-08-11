PREFIX ?= /usr/local
BIN = `which expresso`
JSCOV = deps/jscoverage/node-jscoverage
DOCS = docs/index.md
HTMLDOCS = $(DOCS:.md=.html)
NODE = node
NODEUNIT = deps/nodeunit/bin/nodeunit

integration:
	@$(NODEUNIT) test/symmetric/block test/symmetric/stream test/symmetric/block/aead test/mac test/hash test/asymmetric test/interface
	# @$(NODE) test/test_all.js
	

# unit:
# 	$(BIN) -I lib --growl $(TEST_FLAGS) test/*.test.js
# 
# unit-cov:
# 	$(BIN) -I lib --cov $(TEST_FLAGS) test/*.test.js
# 
# unit-serial:
# 	$(BIN) --serial -I lib $(TEST_FLAGS) test/serial/*.test.js
# 
# test_all:
# 	@$(NODE) test/test_all.js
