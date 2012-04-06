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
from lxml import etree
from base64 import b64encode
from models import Report

def parse(document):
    root = etree.parse(document)    
    report = Report() # @TODO generated report-uuid
      
    # Fill the scan_info dictionary
    report.scan_info['scan_start'] = root.xpath('//@startstr')[0]
    report.scan_info['scan_end'] = root.xpath('//@timestr')[0]
    report.scan_info['command'] = root.xpath('//@args')[0]
    report.scan_info['version'] = root.xpath('//@version')[0]
    report.scan_info['extrainfo'] = root.xpath('//@summary')[0]

    # iterate over ports
    for result in root.xpath('//ports/port'):
        print result[0].tag

if __name__ == '__main__':
    nmap_xml_report = file('../../docs/report-samples/nmap-localhost-2012_04_02.xml', 'r')
    report = parse(nmap_xml_report)
    #print report.printFullReport()