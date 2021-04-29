# Configuration
DRNED  ?= ../../../drned
NEDDIR ?= $(shell (cd ../.. && pwd))

all: 10min 100min 1000min

include $(DRNED)/make/Makefile

OPT = -s --tb=short --device=netsim-0

# Test targets for development use
10min: simple_tests
.PHONY: 10min

100min:
	 py.test -s --tb=short -k 'test_here_ok[' $(OPT)

.PHONY: 100min

1000min:
.PHONY: 1000min

setup-netsim:
	@ncs_cli -u admin -C scripts/setup-netsim
.PHONY: setup-netsim
