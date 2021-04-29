all: test

test:
	@if [ "$$NCS_DIR" = "" ]; then \
	    echo 'Please source NCS environment first!'; \
	    false; \
	fi
	$(MAKE) -C drned env.sh
	(. drned/env.sh ; $(MAKE) -C drned start 10min)
