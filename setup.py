#!/usr/bin/env python

from distutils.core import setup

import web # need python-webpy
import pcap # need python-libpcap package

setup(name='netbars',
      version='1.0',
      description='network traffic monitor with web UI',
      author='Drew Perttula',
      author_email='drewp@bigasterisk.com',
      url='',
      packages=['netbars'],
      scripts=['scripts/netbars', 'scripts/netbars2graphite'],
      package_data={'netbars' : ['bars.html']},
     )