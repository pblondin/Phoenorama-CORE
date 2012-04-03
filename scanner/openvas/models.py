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
Created on Mar 29, 2012

@author: r00tmac
'''
class Openvas():

    def __init__(self):
        self.name = ''
        self.description = ''
        self.target = ''
        self.task_uuid = ''
        self.report_uuid = ''
        self.status = ''

class Report():
    def __init__(self, reportUuid=''):
        self.reportUuid = reportUuid
        self.scan_info = {
                            "_type": "OPENVAS",
                            "task_uuid" : "",
                            "scan_start" : "",
                            "scan_stop": "",
                            "targets": "",
                            "command": "",
                            "version": ""
                          }
        self.results_by_host = {
                                    "hostname" : "",
                                    "results" : [
                                            {
                                                "description" : "",
                                                "service" : "",
                                                "bid" : "",
                                                "risk_factor" : "",
                                                "threat" : "",
                                                "nvtid" : "",
                                                "cve" : "",
                                                "cvss" : "",
                                                "name" : ""                    
                                            }
                                        ]
                                }
                                 
    def getHosts(self):
        return set(self.results_by_host.keys())
    
    def getHighestThreat(self, host):
        threats = [vuln['threat'] for vuln in self.results_by_host[host]]
        
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
            buf += "\tNumber of vulnerabilities: " + str(len(self.results_by_host[host])) + "\n"
        return buf
        
    def printHostResult(self, host):
        buf = "Host: " + host + "\n"
        buf += "Highest threat: " + self.getHighestThreat(host) + "\n"
        buf += "\nList of vulnerabilities: \n"
        for vuln in self.results_by_host[host]:
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
