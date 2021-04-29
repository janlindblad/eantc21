# Set MAIN YANG module to empty in case the NED will handle multiple models
# This is typically the case with RESTCONF NEDs for devices supporting IETF
# models. 
MAIN_YANG_MODULE = tailf-ned-nokia-nsp.yang
PACKAGE_NAME=nsp

# If the NED supports extra stats models in addition to the
# regular one, then add them to EXTRA_YANG_STATS_MODULES.
# Example: ietf-interfaces.yang ietf-ip.yang
EXTRA_YANG_STATS_MODULES=

# Set to yes if the config data models shall be augmented
# into the NSO live-status as well.
BUILD_CONFIG_MODELS_AS_STATS=yes

all: all_gen

include nedcom.mk

