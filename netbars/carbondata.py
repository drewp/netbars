"""
upload data to a carbon server (http://graphite.wikidot.com/carbon) from twisted

This is copied from another project that I haven't released well
enough. A newer version may be at
http://bigasterisk.com/darcs/?r=room;a=headblob;f=/carbondata.py
"""
from __future__ import division
import time
from twisted.internet.protocol import Protocol, ReconnectingClientFactory
from twisted.internet import reactor

class CarbonFactory(ReconnectingClientFactory):
    protocol = Protocol

class CarbonClient(object):
    def __init__(self, serverHost="localhost", port=2003):
        self.carbonFactory = CarbonFactory()

        self.conn = reactor.connectTCP(serverHost, port, self.carbonFactory)
        
    def send(self, metricPath, value, timestamp="now"):
        # quietly fails if the connection isn't ready yet :(
        if timestamp == "now":
            timestamp = time.time()
        # carbon quietly ignores floating-point times
        self.conn.transport.write("%s %f %d\n" % (str(metricPath), # no unicode
                                                  value, timestamp))

