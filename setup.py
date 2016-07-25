#!/usr/bin/env python

from distutils.core import setup

import cyclone.web 
import pcap # need python-libpcap package
import docopt # need python-docopt

setup(name='netbars',
      version='2.0',
      description='network traffic monitor with web UI',
      author='Drew Perttula',
      author_email='drewp@bigasterisk.com',
      url='http://bigasterisk.com/netbars/',
      download_url="http://projects.bigasterisk.com/netbars/netbars-2.0.tar.gz",
      packages=['netbars'],
      scripts=['scripts/netbars', 'scripts/netbars2influxdb'],
      package_data={'netbars' : ['bars.html']},
     )
