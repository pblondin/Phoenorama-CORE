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
        self.task_uuid = ''
        self.name = ''
        self.description = ''
        self.target = ''
        self.report_uuid = ''
        self.status = ''
        
    def toJSON(self):
        json = {'task_uuid' : self.task_uuid,
                'report_uuid' : self.report_uuid,
                'name': self.name,
                'description': self.description,
                'target': self.target,
                'status': self.status
                }
        return json

class Report():
    def __init__(self, reportUuid=''):
        self.reportUuid = reportUuid
        self.scan_info = {}
        self.results_by_host = {}
                                 
    def getHosts(self):
        return self.results_by_host.keys()
    
    def getHighestThreat(self, hostname):
        threats = [results['threat'] for results in self.results_by_host[hostname]]
        
        if 'High' in threats: return 'High'
        elif 'Medium' in threats: return 'Medium'
        elif 'Low' in threats: return 'Low'
        elif 'Log' in threats: return 'Log'
        else: return 'False Positive'
        
    def printSummary(self):
        buf = ""
        for hostname in self.getHosts():
            buf += "Host: " + hostname + "\n"
            buf += "\tThreat: " + self.getHighestThreat(hostname) + "\n"
            buf += "\tNumber of vulnerabilities: " + str(len(self.results_by_host[hostname])) + "\n"
        return buf
        
    def printHostResult(self, hostname):
        buf = "Host: " + hostname + "\n"
        buf += "Highest threat: " + self.getHighestThreat(hostname) + "\n"
        buf += "\nList of vulnerabilities: \n"
        for result in self.results_by_host[hostname]:
            if result['name']:
                buf += "\tName: " + result['name'] + "\n"
            if result['service']:
                buf += "\tService: " + result['service'] + "\n"
            if result['description']:
                buf += "\tDescription: " + result['description'] + "\n"
            if result['threat']:
                buf += "\tThreat: " + result['threat'] + "\n"
            if result['risk_factor']:
                buf += "\tRisk factor: " + result['risk_factor'] + "\n"
            if result['cvss']:
                buf += "\tCVSS: " + result['cvss'] + "\n"
            if result['nvtid']:
                buf += "\tNVTID: " + result['nvtid'] + "\n"
            if result['cve']:
                buf += "\tCVE: " + result['cve'] + "\n"
            if result['bid']:
                buf += "\tBID: " + result['bid'] + "\n"
            buf += "\n"
        return buf
    
    def printFullReport(self):
        buf = "Report summary\n"
        buf += "----------------------\n"
        buf += self.printSummary() + "\n"
        buf += "Detailed report\n"
        buf += "----------------------\n"
        for hostname in self.getHosts():
            buf += self.printHostResult(hostname) + "\n"
        return buf
    
    def __str__(self):
        return self.printSummary()
    
    def toJSON(self):
        json = {'report_uuid' : self.reportUuid,
                'scan_info' : self.scan_info,
                'results_by_host': self.results_by_host
                }
        return json
