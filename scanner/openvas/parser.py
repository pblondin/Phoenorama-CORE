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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#
#######

'''
Created on Mar 27, 2012

@author: r00tmac
'''

from lxml import etree

class Report():
    def __init__(self, reportUuid=''):
        self.reportUuid = reportUuid
        self.open_ports_by_host = {}         # using host as key
        self.vulnerabilities_by_host = {}    # using host as key
        
    def getHosts(self):
        return set(self.open_ports_by_host.keys() + self.vulnerabilities_by_host.keys())
    
    def getHighestThreat(self, host):
        threats = [vuln['threat'] for vuln in self.vulnerabilities_by_host[host]]
        
        if 'High' in threats: return 'High'
        elif 'Medium' in threats: return 'Medium'
        elif 'Low' in threats: return 'Low'
        elif 'Log' in threats: return 'Log'
        else: return 'False Positive'
        
    def printSummary(self):
        buf = ""
        for host in self.getHosts():
            buf += "Host: " + host + "\n"
            buf += "\tThreat: " + self.getHighestThreat(host) + "\n"
            buf += "\tNumber of open ports: " + str(len(self.open_ports_by_host[host])) + "\n"
            buf += "\tNumber of vulnerabilities: " + str(len(self.vulnerabilities_by_host[host])) + "\n"
        return buf
        
    def printHostResult(self, host):
        buf = "Host: " + host + "\n"
        buf += "Highest threat: " + self.getHighestThreat(host) + "\n"
        buf += "List of open ports: \n"
        for port in self.open_ports_by_host[host]:
            buf += "\t" + port + "\n"
        buf += "\nList of vulnerabilities: \n"
        for vuln in self.vulnerabilities_by_host[host]:
            buf += "\tName: " + vuln['name'] + "\n"
            buf += "\tService: " + vuln['service'] + "\n"
            buf += "\tDescription: " + vuln['description'] + "\n"
            buf += "\tThreat: " + vuln['threat'] + "\n"
            if vuln['risk_factor']:
                buf += "\tRisk factor: " + vuln['risk_factor'] + "\n"
            if vuln['cvss']:
                buf += "\tCVSS: " + vuln['cvss'] + "\n"
            if vuln['nvtid']:
                buf += "\tNVTID: " + vuln['nvtid'] + "\n"
            if vuln['cve']:
                buf += "\tCVE: " + vuln['cve'] + "\n"
            if vuln['bid']:
                buf += "\tBID: " + vuln['bid'] + "\n"
            buf += "\n"        
        return buf
    
    def printFullReport(self):
        buf = "Report summary\n"
        buf += "----------------------\n"
        buf += self.printSummary() + "\n"
        buf += "Detailed report\n"
        buf += "----------------------\n"
        for host in self.getHosts():
            buf += self.printHostResult(host) + "\n"
        return buf
    
    def __str__(self):
        return self.printSummary()
    
    
    def toJSON(self):
        jsonReport = {'report_uuid': self.reportUuid, 
                      'open_ports': [], 
                      'vulnerabilities': []
                      }
        for host in self.getHosts():
            jsonReport['open_ports'].append({'host': host, 'ports': self.open_ports_by_host[host] })
            jsonReport['vulnerabilities'].append({'host': host, 'vulnerabilities': self.vulnerabilities_by_host[host]})
        return jsonReport
                                

def parseXML(document):
    root = etree.parse(document)
    report = Report(root.xpath('/report/@id')[0])
    
    vulnerabilities = {}
    # iterate over vulnerabilities
    for result in root.xpath('//result'):
        host = result.xpath('host')[0].text
        if not vulnerabilities.has_key(host):
            vulnerabilities[host] = []
            
        vuln = {}
        
        # Summary
        vuln['description'] = result.xpath('description')[0].text.strip()
        vuln['name'] = result.xpath('nvt/name')[0].text
        vuln['service'] = result.xpath('port')[0].text
        
        # Risk
        vuln['risk_factor'] = result.xpath('nvt/risk_factor')[0].text
        vuln['cvss'] = result.xpath('nvt/cvss_base')[0].text
        vuln['threat'] = result.xpath('threat')[0].text
        
        # References
        vuln['nvtid'] = result.xpath('nvt/@oid')[0] #oid attribute
        cve = result.xpath('nvt/cve')[0].text
        vuln['cve'] = cve if cve != 'NOCVE' else None
        bid = result.xpath('nvt/bid')[0].text
        vuln['bid'] = bid if bid != 'NOBID' else None
        
        # add vuln to vulnerabilities dictionary
        vulnerabilities[host].append(vuln)
      
    openPorts = {}
    # iterate over open ports
    for port in root.xpath('//ports/port'):
        host = port.xpath('host')[0].text
        if not openPorts.has_key(host):
            openPorts[host] = []
        
        # add port to open ports dictionary
        openPorts[host].append(port.text)
        
    report.open_ports_by_host = openPorts
    report.vulnerabilities_by_host = __cleanupVulnerabilities(vulnerabilities)
    return report

def __cleanupVulnerabilities(vulnerabilities):
    # get rid of general information and open ports (duplicate information)
    filterOIDs = ['1.3.6.1.4.1.25623.1.0.900239',  # open tcp ports
                 '1.3.6.1.4.1.25623.1.0.103978',   # open upd ports
                 '1.3.6.1.4.1.25623.1.0.51662',    # traceroute
                 '1.3.6.1.4.1.25623.1.0.90022',    # ssh autorization
                 '1.3.6.1.4.1.25623.1.0.90011',    # smbclient not available
                 '1.3.6.1.4.1.25623.1.0.66286',    # unknown service
                 '1.3.6.1.4.1.25623.1.0.810003',   # host summary
                 '1.3.6.1.4.1.25623.1.0.19506',    # scan information
                 '1.3.6.1.4.1.25623.1.0.103079'    # DIRB (NASL wrapper)
                 '1.3.6.1.4.1.25623.1.0.110001',   # arachni (NASL wrapper)
                 '1.3.6.1.4.1.25623.1.0.14260',    # nikto (NASL wrapper)
                 '1.3.6.1.4.1.25623.1.0.80110'     # wapiti (NASL wrapper)
                 ]
    isNotGeneralInfo = lambda vuln: vuln['nvtid'] not in filterOIDs and True or False
    isNotOpenPort = lambda vuln: vuln['description'] != 'Open port.' and True or False
    for k in vulnerabilities:
        vulnerabilities[k] = filter(isNotGeneralInfo, vulnerabilities[k])
        vulnerabilities[k] = filter(isNotOpenPort, vulnerabilities[k])
    return vulnerabilities

if __name__ == '__main__':
    openvas_xml_report = file('../../docs/report-samples/openvas-2hosts-2012_03_24.xml', 'r')
    report = parseXML(openvas_xml_report)
    print report.printFullReport()
              
            