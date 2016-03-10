import logging
import random
import wishful_upis as upis
import wishful_framework as wishful_module

__author__ = "Piotr Gawlowicz"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz}@tkn.tu-berlin.de"


@wishful_module.build_module
class LinuxNetModule(wishful_module.AgentModule):
    def __init__(self):
        super(LinuxNetModule, self).__init__()
        self.log = logging.getLogger('LinuxNetModule')

    @wishful_module.bind_function(upis.radio.set_channel)
    def set_channel(self, channel):
        self.log.debug("Simple Module sets channel: {} on interface: {}".format(channel, self.interface))
        self.channel = channel
        return ["SET_CHANNEL_OK", channel, 0]