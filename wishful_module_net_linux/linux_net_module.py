import os
import logging
import random
import subprocess
import inspect
import fcntl, socket, struct
import netifaces as ni
from datetime import date, datetime
import copy
import iptc
from pytc.TrafficControl import TrafficControl
from pytc.Profile import Profile
from pytc.Filter import FlowDesc
import pytc.Qdisc
import pytc.Filter
from pyroute2 import IPDB

import wishful_upis as upis
from wishful_agent.core import exceptions
import wishful_agent.core as wishful_module

# TODO:piotr, do we need this???
#from wishful_framework.upi_arg_classes.flow_id import FlowId
#from wishful_framework.upi_arg_classes.iptables import SimpleMatch, SimpleTarget, SimplePolicy, SimpleRule, SimpleChain, SimpleTable

__author__ = "Piotr Gawlowicz, Anatolij Zubow"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz, zubow}@tkn.tu-berlin.de"


@wishful_module.build_module
class NetworkModule(wishful_module.AgentModule):
    def __init__(self):
        super(NetworkModule, self).__init__()
        self.log = logging.getLogger('NetworkModule')


    @wishful_module.bind_function(upis.net.get_ifaces)
    def get_ifaces(self):
        """Return the list of interface names
        """
        self.log.info('get_ifaces() called')
        retVal = ni.interfaces()
        return retVal


    @wishful_module.bind_function(upis.net.get_iface_hw_addr)
    def get_iface_hw_addr(self, iface):
        """Return the MAC address of a particular interface
        """
        try:
            self.log.info('get_iface_hw_addr() called {}'.format(iface))
            retVal = ni.ifaddresses(iface)[ni.AF_LINK][0]['addr']
            return retVal
        except Exception as e:
            self.log.fatal("Failed to get HW address for %s, err_msg:%s" % (iface, str(e)))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=inspect.currentframe().f_code.co_name,
                                                                 err_msg='Failed to get HW addr: ' + str(e))


    @wishful_module.bind_function(upis.net.get_iface_ip_addr)
    def get_iface_ip_addr(self, iface):
        """Interfaces may have multiple addresses, return a list with all addresses
        """
        try:
            self.log.info('get_iface_ip_addr() called {}'.format(iface))
            ipList = [inetaddr['addr'] for inetaddr in ni.ifaddresses(iface)[ni.AF_INET]]
            return ipList
        except Exception as e:
            self.log.fatal("Failed to get IP address for %s, err_msg:%s" % (iface, str(e)))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=inspect.currentframe().f_code.co_name,
                                                                 err_msg='Failed to get IP addr: ' + str(e))

    @wishful_module.bind_function(upis.net.set_ARP_entry)
    def set_ARP_entry(self, iface, mac_addr, ip_addr):
        """
            Manipulates the local ARP cache.
            TODO: use Netlink API
        """
        try:
            [rcode, sout, serr] = self.run_command('sudo arp -s ' + ip_addr + ' -i '+ iface + ' ' + mac_addr)
            return sout
        except Exception as e:
            self.log.fatal("Failed to set ARP entry for iface:%s, err_msg:%s" % str(e))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=inspect.currentframe().f_code.co_name,
                                                                 err_msg='Failed to set ARP entry: ' + str(e))


    @wishful_module.bind_function(upis.net.change_routing)
    def change_routing(self, serving_gw_ip_addr, target_gw_ip_addr, dst_ip_addr):
        '''
            IPDB has a simple yet useful routing management interface.
            To add a route, one can use almost any syntax::
            pass spec as is
            r = self.ip.routes.get('192.168.5.0/24')
        '''
        try:
            ip = IPDB(mode='direct')
            r = ip.routes.get(dst_ip_addr + '/32')
            if not r.gateway:
                self.log.info("Currently no gateway found, creating it...")
                ip.routes.add(dst=dst_ip_addr + '/32', gateway=target_gw_ip_addr).commit()
            else:
                self.log.info("Old gateway = %s for %s" % (r.gateway, dst_ip_addr))

                if (r.gateway.startswith(serving_gw_ip_addr) or r.gateway.startswith(target_gw_ip_addr)):
                    r.remove()

                ip.routes.add(dst=dst_ip_addr + '/32', gateway=target_gw_ip_addr).commit()

                r = ip.routes.get(dst_ip_addr + '/32')
                self.log.info("New gateway = %s for %s" % (r.gateway, dst_ip_addr))

            ip.release()
            return True

        except Exception as e:
            self.log.fatal("Failed to change routing, err_msg:%s" % str(e))
            raise exceptions.UPIFunctionExecutionFailedException(func_name=inspect.currentframe().f_code.co_name,
                                                                 err_msg='Failed to change routing: ' + str(e))

    @wishful_module.bind_function(upis.net.set_netem_profile)
    def set_netem_profile(self, iface, profile):
        self.log.debug('set_profile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.setProfile(profile)
        return True


    @wishful_module.bind_function(upis.net.update_netem_profile)
    def update_netem_profile(self, iface, profile):
        self.log.debug('updateProfile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.updateProfile(profile)
        return True


    @wishful_module.bind_function(upis.net.remove_netem_profile)
    def remove_netem_profile(self, iface):
        self.log.debug('removeProfile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.clean()
        return True


    @wishful_module.bind_function(upis.net.set_per_link_netem_profile)
    def set_per_link_netem_profile(self, iface, dstIpAddr, profile):
        self.log.debug('setPerLinkProfile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.setPerLinkProfile(profile, dstIpAddr)
        return True


    @wishful_module.bind_function(upis.net.remove_per_link_netem_profile)
    def remove_per_link_netem_profile(self, iface, dstIpAddr):
        self.log.debug('removePerLinkProfile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.cleanPerLinkProfile(dstIpAddr)
        return True


    @wishful_module.bind_function(upis.net.update_per_link_netem_profile)
    def update_per_link_netem_profile(self, iface, dstIpAddr, profile):
        self.log.debug('updatePerLinkProfile on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.updatePerLinkProfile(profile, dstIpAddr)
        return True


    @wishful_module.bind_function(upis.net.install_egress_scheduler)
    def install_egress_scheduler(self, iface, scheduler):
        self.log.debug('installEgressScheduler on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.setEgressScheduler(scheduler)
        return True


    @wishful_module.bind_function(upis.net.remove_egress_scheduler)
    def remove_egress_scheduler(self, iface):
        self.log.debug('removeEgressScheduler on interface: {}'.format(iface))

        tcMgr = TrafficControl()
        intface = tcMgr.getInterface(iface)
        intface.clean()
        tcMgr.cleanIpTables()
        return True


    @wishful_module.bind_function(upis.net.clear_nf_tables)
    def clear_nf_tables(self, table="ALL", chain="ALL"):
        self.log.debug('clearIpTables'.format())

        tables = []
        chains = {}

        if table == "ALL":
            tables = ["raw", "mangle", "nat", "filter"]
        else:
            if not isinstance(table, list):
                table = [table]
            tables.extend(table)

        if chain == "ALL":
            chains["filter"] = ["INPUT","FORWARD","OUTPUT"]
            chains["nat"] = ["PREROUTING", "OUTPUT", "POSTROUTING"]
            chains["mangle"] = ["PREROUTING", "OUTPUT", "INPUT", "FORWARD", "POSTROUTING"]
            chains["raw"] = ["PREROUTING", "OUTPUT"]
        else:
            if not isinstance(chain, list):
                chain = [chain]
            chains[tables[0]].extend(chain)

        for tableName in tables:
            for chainName in chains[tableName]:
                chain = iptc.Chain(iptc.Table(tableName), chainName)
                chain.flush()

        return True


    @wishful_module.bind_function(upis.net.get_nf_table)
    def get_nf_table(self, tableName):
        self.log.debug('getIpTable'.format())

        #exec embedded function
        table = iptc.Table(tableName)
        #refresh table to get current counters
        table.refresh()
        #create simple table (ie. without pointers to ctypes)
        simpleTable = SimpleTable(table)
        return simpleTable

    @wishful_module.bind_function(upis.net.set_pkt_marking)
    def set_pkt_marking(self, flowId, markId=None, table="mangle", chain="POSTROUTING"):
        self.log.debug('setMarking'.format())

        if not markId:
            tcMgr = TrafficControl()
            markId = tcMgr.generateMark()

        rule = iptc.Rule()

        if flowId.srcAddress:
            rule.src = flowId.srcAddress

        if flowId.dstAddress:
            rule.dst = flowId.dstAddress

        if flowId.prot:
            rule.protocol = flowId.prot
            match = iptc.Match(rule, flowId.prot)

            if flowId.srcPort:
                match.sport = flowId.srcPort

            if flowId.dstPort:
                match.dport = flowId.dstPort

            rule.add_match(match)

        target = iptc.Target(rule, "MARK")
        target.set_mark = str(markId)
        rule.target = target
        chain = iptc.Chain(iptc.Table(table), chain)
        chain.insert_rule(rule)
        return markId


    @wishful_module.bind_function(upis.net.del_pkt_marking)
    def del_pkt_marking(self, flowId, markId, table="mangle", chain="POSTROUTING"):
        #TODO: store table and chain per flowId/mark in set_pkt_marking,
        #it should be possible to remove marking only with flowId/markId
        self.log.debug('delMarking'.format())

        rule = iptc.Rule()

        if flowId.srcAddress:
            rule.src = flowId.srcAddress

        if flowId.dstAddress:
            rule.dst = flowId.dstAddress

        if flowId.prot:
            rule.protocol = flowId.prot
            match = iptc.Match(rule, flowId.prot)

            if flowId.srcPort:
                match.sport = flowId.srcPort

            if flowId.dstPort:
                match.dport = flowId.dstPort

            rule.add_match(match)

        target = iptc.Target(rule, "MARK")
        target.set_mark = str(markId)
        rule.target = target
        chain = iptc.Chain(iptc.Table(table), chain)
        chain.delete_rule(rule)
        return True


    @wishful_module.bind_function(upis.net.set_ip_tos)
    def set_ip_tos(self, flowId, tos, table="mangle", chain="POSTROUTING"):
        self.log.debug('setTos'.format())

        rule = iptc.Rule()

        if flowId.srcAddress:
            rule.src = flowId.srcAddress

        if flowId.dstAddress:
            rule.dst = flowId.dstAddress

        if flowId.prot:
            rule.protocol = flowId.prot
            match = iptc.Match(rule, flowId.prot)

            if flowId.srcPort:
                match.sport = flowId.srcPort

            if flowId.dstPort:
                match.dport = flowId.dstPort

            rule.add_match(match)

        target = iptc.Target(rule, "TOS")
        target.set_tos = str(tos)
        rule.target = target
        chain = iptc.Chain(iptc.Table(table), chain)
        chain.insert_rule(rule)
        return True


    @wishful_module.bind_function(upis.net.del_ip_tos)
    def del_ip_tos(self, flowId, tos, table="mangle", chain="POSTROUTING"):
        #TODO: store table and chain per flowId/mark in set_pkt_marking,
        #it should be possible to remove marking only with flowId/markId
        self.log.debug('delTos'.format())

        rule = iptc.Rule()

        if flowId.srcAddress:
            rule.src = flowId.srcAddress

        if flowId.dstAddress:
            rule.dst = flowId.dstAddress

        if flowId.prot:
            rule.protocol = flowId.prot
            match = iptc.Match(rule, flowId.prot)

            if flowId.srcPort:
                match.sport = flowId.srcPort

            if flowId.dstPort:
                match.dport = flowId.dstPort

            rule.add_match(match)

        target = iptc.Target(rule, "TOS")
        target.set_tos = str(tos)
        rule.target = target
        chain = iptc.Chain(iptc.Table(table), chain)
        chain.delete_rule(rule)
        return True
