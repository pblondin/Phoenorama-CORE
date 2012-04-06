#######
#
# Copyright (C) 2012 Phoenorama.org All Rights Reserved.
# Author: Philippe Blondin <pblondin@phoenorama.org>>
#
# This file is part of the Phoenorama program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#
#######

'''
Created on Apr 2, 2012

@author: r00tme
'''
import uuid
from lxml import etree
from base64 import b64encode
from models import Report

def parse(document):
    root = etree.parse(document)    
    report = Report(uuid.uuid4())
      
    # Fill the scan_info dictionary
    report.scan_info['scan_start'] = root.xpath('//@startstr')[0]
    report.scan_info['scan_end'] = root.xpath('//@timestr')[0]
    report.scan_info['command'] = root.xpath('//@args')[0]
    report.scan_info['version'] = root.xpath('//@version')[0]
    report.scan_info['extrainfo'] = root.xpath('//@summary')[0]

    # iterate over host
    for result in root.xpath('//host'):
        
        #@TODO : add safety net
        hostname =  b64encode(result.xpath('hostnames/hostname[@type = "user"]/@name')[0]) # hostname has to be base64 encode to prevent "." in key (mongodb issue)

        # check if result already exist for the hostname
        if not report.results_by_host.has_key(hostname):
            report.results_by_host[hostname] = []

        # iterate over ports
        for port in result.xpath('ports/port'):
            vuln = {}
            
            vuln['portid'] = port.xpath('@portid')[0]
            vuln['service'] = port.xpath('service/@name')[0]
            vuln['product'] = port.xpath('service/@product')[0]
            vuln['version'] = port.xpath('service/@version')[0]
            
            # get script info
            vuln['scriptid'] = port.xpath('script/@id')[0]
            vuln['output'] = port.xpath('script/@output')[0]
            
            # append vulnerability to results list
            report.results_by_host[hostname].append(vuln)

    return report

if __name__ == '__main__':
    nmap_xml_report = file('../../docs/report-samples/nmap-localhost-2012_04_02.xml', 'r')
    report = parse(nmap_xml_report)
    print report.printFullReport()
    
    
    
    
    