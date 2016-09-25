import logging
import datetime
import time
import random
import wishful_upis as upis
from wishful_agent.core import wishful_module
from wishful_agent.timer import TimerEventSender

__author__ = "Anatolij Zubow"
__copyright__ = "Copyright (c) 2016, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{zubow}@tkn.tu-berlin.de"

'''
Local test of net linux component.
'''

@wishful_module.build_module
class NetLinuxController(wishful_module.ControllerModule):
    def __init__(self):
        super(NetLinuxController, self).__init__()
        self.log = logging.getLogger('NetLinuxController')

    @wishful_module.on_start()
    def my_start_function(self):
        self.log.info("start net linux test")

        try:
            node = self.localNode

            iface = 'lo'
            if_hw_addr = node.net.get_iface_hw_addr(iface)
            self.log.info('Net Linux client: iface %s, hw_addr %s' % (iface, str(if_hw_addr)))



            self.log.info('... done')

        except Exception as e:
            self.log.error("{} Ctrl:: !!!Exception!!!: {}".format(datetime.datetime.now(), e))


    @wishful_module.on_exit()
    def my_stop_function(self):
        self.log.info("stop net linux test")
