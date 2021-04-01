# -*- mode: python; python-indent: 4 -*-
import ncs
from ncs.application import Service
import hashlib

logger = None

def md5_hash(val, modulus_val=None):
    md5_val = hashlib.md5(str(val).encode('utf-8'))
    int_val = int.from_bytes(md5_val.digest()[:4], byteorder='big')
    if modulus_val:
        return int_val % modulus_val
    return int_val

def t(traced_value):
    from inspect import currentframe, getframeinfo
    logger.info(f"T#{getframeinfo(currentframe()).lineno}: {traced_value}.")
    return traced_value

class ServiceCallbacks(Service):
    @Service.create
    def cb_create(self, tctx, root, service, proplist):

        def prefixlen2mask(prefixlen):
            masks = {
                24: "255.255.255.0", 32: "255.255.255.255"
            }
            return masks[prefixlen]

        def allocate_vlan_id(vpn_id):
            try:
                numeric = int(vpn_id)
                if numeric >= 100 and numeric <= 4000:
                    return nume
            except:
                pass
            return md5_hash(vpn_id, modulus_val=3900)+100

        def interface_type(interface):
            for interface_type in ["GigabitEthernet", "25GE"]:
                if interface_type in interface:
                    return interface_type
            return "Unknown"

        def allocate_rd(device_name):
            return { 
                "hw1": "4",
                "hwx4": "5",
            }.get(device_name)

        def allocate_label(device_name):
            return { 
                "hw1": "100",
                "hwx4": "200",
            }.get(device_name)

        def allocate_subif(edge_interface):
            return { 
                "GigabitEthernet0/1/9": "4",
                "25GE3/0/70": "4",
            }.get(edge_interface)

        def edge_interface_lookup(device_name):
            return { 
                "hw1": "GigabitEthernet0/1/9",
                "hwx4": "25GE3/0/70",
            }.get(device_name)

        def apply_template(template_applier, template_name, **kwargs):
            bindings = ncs.template.Variables()
            for key, value in kwargs.items():
                bindings.add(key, value)
            self.log.info(f"Applying template '{template_name}' with bindings {bindings}")
            template_applier.apply(template_name, bindings)

        global logger
        logger = self.log
        self.log.info('Service create(service=', service._path, ')')
        applier = ncs.template.Template(service)

        for sna in service.site_network_accesses.site_network_access:
            # sna.device_reference .ip_connection .service .vpn_attachment
            self.log.info(f'Processing site_network_access {sna.site_network_access_id}')
            pe_topo = root.topo[sna.vpn_attachment.vpn_id, sna.device_reference]
            # pe_topo.vpn_name .device_name .connected_to_device .router_id .isis_net_entity .interface .core_address .core_prefixlen
            remote_topo = root.topo[sna.vpn_attachment.vpn_id, pe_topo.connected_to_device]
            self.log.info(f'Configuring pe device {pe_topo.device_name}')
            edge_interface = edge_interface_lookup(pe_topo.device_name)
            self.log.info(f'Conf2 {edge_interface}')
            apply_template(applier, 'l3vpn-template', 
                DEVICE = t(pe_topo.device_name),
                VRF_NAME = t(sna.vpn_attachment.vpn_id), # "eantc"
                VLAN_ID = t(allocate_vlan_id(sna.vpn_attachment.vpn_id)),
                LOGICAL_PORT = t(pe_topo.interface),#19,
                SHELF_SLOT = t(pe_topo.shelf_slot),#"1_14",
                IF_IP = t(pe_topo.core_address),#"10.19.100.1",
                AS_NUM = t(pe_topo.as_number),#65432
                PEER_IP = t(root.topo[sna.vpn_attachment.vpn_id,pe_topo.connected_to_device].core_address),#"10.19.100.2",
                PEER_AS_NUM = t(root.topo[sna.vpn_attachment.vpn_id,pe_topo.connected_to_device].as_number),#"65105"
                PEER_DEVICE_NAME = t(pe_topo.connected_to_device),#spirent
                NODE_ID = t(md5_hash(pe_topo.device_name, modulus_val=990)+10),
                SERVICE_ID = t(allocate_vlan_id(sna.vpn_attachment.vpn_id)),#100


                #DEVICE = pe_topo.device_name,
                #AS = sna.vpn_attachment.vpn_id,
                #RD = allocate_rd(pe_topo.device_name),
                #LABEL = allocate_label(pe_topo.device_name),
                #ISIS_NET_ENTITY = pe_topo.isis_net_entity,
                #SOURCE_ADDRESS = pe_topo.router_id,
                #DESTINATION_ADDRESS = remote_topo.router_id,
                #CORE_INTERFACE = pe_topo.interface,
                #CORE_ADDRESS = pe_topo.core_address,
                #CORE_PREFIXLEN = pe_topo.core_prefixlen,
                #CORE_MASK = prefixlen2mask(pe_topo.core_prefixlen),
                #EDGE_INTERFACE = edge_interface,
                #EDGE_SUBINTERFACE = allocate_subif(edge_interface),
                #EDGE_INTERFACE_TYPE = interface_type(edge_interface),
                #EDGE_ADDRESS = sna.ip_connection.ipv4.addresses.provider_address,
                #EDGE_PREFIXLEN = sna.ip_connection.ipv4.addresses.prefix_length,
                #EDGE_MASK = prefixlen2mask(sna.ip_connection.ipv4.addresses.prefix_length),
                #EDGE_ADDRESS_IPV6 = sna.ip_connection.ipv6.addresses.provider_address,
                #EDGE_PREFIXLEN_IPV6 = sna.ip_connection.ipv4.addresses.prefix_length,
                #PEER_ADDRESS = sna.ip_connection.ipv4.addresses.customer_address,
                #PEER_ADDRESS_IPV6 = sna.ip_connection.ipv6.addresses.customer_address,
                #PEER_AS = "110"
            )
        self.log.info('Service create done')

class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('l3vpn-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')
