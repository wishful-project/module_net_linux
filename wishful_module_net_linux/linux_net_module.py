import logging
import random
import wishful_upis as upis
import wishful_framework as wishful_module
import subprocess
from wishful_framework.classes import exceptions
import inspect
import fcntl, socket, struct
import netifaces as ni
from datetime import date, datetime
import os


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

        self.log.info('getHwAddr() called {}'.format(iface))
        retVal = ni.ifaddresses(iface)[ni.AF_LINK]
        #retVal = list(retVal[0].values())[1]
        retVal = retVal[0]
        retVal = retVal['addr']
        return retVal


    @wishful_module.bind_function(upis.net.get_iface_ip_addr)
    def get_iface_ip_addr(self, iface):

        ip = ni.ifaddresses(iface)[2][0]['addr']
        return ip


    @wishful_module.bind_function(upis.net.change_routing)
    def change_routing(self, servingAP_ip_addr, targetAP_ip_addr, sta_ip_addr):

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


    @wishful_module.bind_function(upis.net.set_ARP_entry)
    def set_ARP_entry(self, iface, mac_addr, ip_addr):
        """
            Manipulates the local ARP cache.
            todo: use Netlink API
        """
        try:
            [rcode, sout, serr] = self.run_command('sudo arp -s ' + ip_addr + ' -i '+ iface + ' ' + mac_addr)
            return sout
        except Exception as e:
            fname = inspect.currentframe().f_code.co_name
            self.log.fatal("An error occurred in %s: %s" % (fname, e))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=fname, err_msg=str(e))
