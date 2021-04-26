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
            self.log.info(f'Processing site_network_access {sna.network_access_id}')
            pe_topo = root.topo[sna.vpn_attachment.vpn_id, sna.device_reference]
            # pe_topo.vpn_name .device_name .connected_to_device .router_id .isis_net_entity .interface .core_address .core_prefixlen
            remote_topo = root.topo[sna.vpn_attachment.vpn_id, pe_topo.connected_to_device]
            self.log.info(f'Configuring pe device {pe_topo.device_name}')
            edge_interface = edge_interface_lookup(pe_topo.device_name)
            self.log.info(f'Conf2 {edge_interface}')
            apply_template(applier, 'evpn-template', 
                DEVICE = t(pe_topo.device_name),
                VLAN_ID = t(allocate_vlan_id(sna.vpn_attachment.vpn_id)),
                AS = t(pe_topo.as_number),
                SVC = t(allocate_vlan_id(sna.vpn_attachment.vpn_id)),
                PE_INTERFACE = t(pe_topo.interface),
                PE_ADDRESS = t(pe_topo.shelf_slot),
                MTU = t(sna.service.svc_mtu),
            )
        self.log.info('Service create done')

class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_service('evpn-servicepoint', ServiceCallbacks)

    def teardown(self):
        self.log.info('Main FINISHED')
