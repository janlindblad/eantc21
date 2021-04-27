# Build a IP Infusion OcNOS ... device NED

NED_NAME = ipi-ocnos4
BUILD_DIR = yangs
REPO_DIR = combined-flat
EXTRA_DIR = yangs-extra
LOAD_DIR = $(NED_NAME)/load-dir
PKGS_DIR = packages
SRC_REPO = $(wildcard $(REPO_DIR)/*.yang)
SRC_EXTRA = $(wildcard $(EXTRA_DIR)/*.yang)
SRC = $(filter-out $(MODULES_DROP), $(SRC_REPO) $(SRC_EXTRA))
MODULES_DROP =

$(BUILD_DIR)/%.yang: $(REPO_DIR)/%.yang
	@cp $< $@

$(BUILD_DIR)/%.yang: $(EXTRA_DIR)/%.yang
	@cp $< $@

# IP Infusion issues

# yang/ipi-oc-ni-augments.yang:14: error: augmenting a mandatory node is illegal
$(BUILD_DIR)/ipi-oc-ni-augments.yang: $(REPO_DIR)/ipi-oc-ni-augments.yang
	grep -v "mandatory true;" $< > $@

# yang/ipi-oc-ni-deviations.yang:46: error: the 'max-elements' property does not exist in the target node
# yang/ipi-oc-ni-deviations.yang:52: error: the 'max-elements' property does not exist in the target node
$(BUILD_DIR)/ipi-oc-ni-deviations.yang: $(REPO_DIR)/ipi-oc-ni-deviations.yang
	awk '/oc-netinst:import-policy {/{d=6} \
		/oc-netinst:network-instance.oc-netinst:encapsulation.oc-netinst:config {/{d=7} \
		{if(d){d--;;$$0="//FIXME "$$0}print}' $< > $@

# error: deviation causes circular dependency between augmented/openconfig-if-8021x@2020-01-28.yang and augmented/openconfig-vlan@2019-04-16.yang
$(BUILD_DIR)/ipi-oc-if-deviations.yang: $(REPO_DIR)/ipi-oc-if-deviations.yang
	awk '/deviation .oc-if:interfaces.oc-if:interface.oc-if:config.oc-if:name {/{if(!done)d=15}{if(d){d--;done=1;$$0="//FIXME "$$0}print}' $< > $@

# error: the node 'subcomponents' from module 'openconfig-platform' (in node 'component' in module 'openconfig-platform' from 'openconfig-platform') is not found
$(BUILD_DIR)/ipi-oc-platform-deviations.yang: $(REPO_DIR)/ipi-oc-platform-deviations.yang
	awk '/deviation .oc-platf:components.oc-platf:component.oc-platf:subcomponents {/{d=3}{if(d){d--;;$$0="//FIXME "$$0}print}' $< > $@

# info illegal reference devices device ipi-31 config network-instances network-instance default protocols protocol STATIC static-routes identifier
# info illegal reference devices device ipi-31 config network-instances network-instance default protocols protocol STATIC static-routes name
$(BUILD_DIR)/openconfig-network-instance.yang: $(REPO_DIR)/openconfig-network-instance.yang
	awk '/leaf identifier {/{if(!done){d=4;print;print "type string;"}} \
		/leaf name {/{thistime++;if(thistime==2){d=4;print;print "type string;"}} \
		{if(d){d--;done=1;$$0="//FIXME "$$0}print}' $< > $@

# OpenConfig issues

# yang/openconfig-srte-policy.yang:428: error: the node 'index' from module 'openconfig-network-instance' (in node 'state' from 'openconfig-network-instance') is not found
$(BUILD_DIR)/openconfig-srte-policy.yang: $(EXTRA_DIR)/openconfig-srte-policy.yang
	awk '/A next-hop the segment list is resolved to./{d=6;print;print "leaf index{type string;"}{if(d){d--;;$$0="//FIXME "$$0}print}' $< > $@

all: $(patsubst %, $(BUILD_DIR)/%, $(notdir $(SRC)))
	-mkdir $(BUILD_DIR)/no
	ncs-make-package --verbose --netconf-ned yangs $(NED_NAME) --no-netsim --no-python --no-java
	FXS_WERR= NCSC_EXTRA_FLAGS=--lax-revision-merge make -C $(NED_NAME)/src clean all

clean:
	-rm yangs/*.yang
