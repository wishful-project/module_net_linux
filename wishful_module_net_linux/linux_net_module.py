import logging
import random
import wishful_upis as upis
import wishful_framework as wishful_module

__author__ = "Piotr Gawlowicz, A.Zubow"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz, zubow}@tkn.tu-berlin.de"


@wishful_module.build_module
class NetworkModule(wishful_module.AgentModule):
    def __init__(self):
        super(NetworkModule, self).__init__()
        self.log = logging.getLogger('NetworkModule')


    @wishful_module.bind_function(upis.net.get_iface_hw_addr)
    def get_iface_hw_addr(self, iface):
        '''
        @todo: move to common network module; it is not wifi specific
        '''

        self.log.info('getHwAddr() called')

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', iface[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

    @wishful_module.bind_function(upis.net.get_iface_ip_addr)
    def get_iface_ip_addr(self, iface):
        '''
        @todo: move to common network module; it is not wifi specific
        '''

        ip = ni.ifaddresses(iface)[2][0]['addr']
        return ip

    @wishful_module.bind_function(upis.net.change_routing)
    def change_routing(self, servingAP_ip_addr, targetAP_ip_addr, sta_ip_addr):
        """
            Manipulates the Linux Routing table.
        """

        # IPDB has a simple yet useful routing management interface.
        # To add a route, one can use almost any syntax::
        # pass spec as is
        # r = self.ip.routes.get('192.168.5.0/24')
        r = self.ip.routes.get(sta_ip_addr + '/32')
        if not r.gateway:
            self.log.info("Currently no gateway found, creating it...")
            self.ip.routes.add(dst=sta_ip_addr + '/32', gateway=targetAP_ip_addr).commit()
        else:
            self.log.info("Old gateway = %s for %s" % (r.gateway, sta_ip_addr))

            if (r.gateway.startswith(servingAP_ip_addr) or r.gateway.startswith(targetAP_ip_addr)):
                r.remove()

            self.ip.routes.add(dst=sta_ip_addr + '/32', gateway=targetAP_ip_addr).commit()

            r = self.ip.routes.get(sta_ip_addr + '/32')
            self.log.info("New gateway = %s for %s" % (r.gateway, sta_ip_addr))

        return True
