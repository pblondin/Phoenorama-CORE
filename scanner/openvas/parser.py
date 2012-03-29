'''
Created on Mar 27, 2012

@author: r00tmac
'''

from lxml import etree

class Report():
    def __init__(self):
        self.open_ports = {}         # using host as key
        self.vulnerabilities = {}    # using host as key
    
    def getHosts(self):
        return set(self.open_ports.keys() + self.vulnerabilities.keys())
    
    def getHighestThreat(self, host):
        threats = [vuln.risk['threat'] for vuln in self.vulnerabilities[host]]
        
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
            buf += "\tNumber of open ports: " + str(len(self.open_ports[host])) + "\n"
            buf += "\tNumber of vulnerabilities: " + str(len(self.vulnerabilities[host])) + "\n"
        return buf
        
    def printHostResult(self, host):
        buf = "Host: " + host + "\n"
        buf += "Highest threat: " + self.getHighestThreat(host) + "\n"
        buf += "List of open ports: \n"
        for port in self.open_ports[host]:
            buf += "\t" + port + "\n"
        buf += "\nList of vulnerabilities: \n"
        for vuln in self.vulnerabilities[host]:
            buf += "\tName: " + vuln.name + "\n"
            buf += "\tService: " + vuln.service + "\n"
            buf += "\tDescription: " + vuln.description + "\n"
            buf += "\tThreat: " + vuln.risk['threat'] + "\n"
            if vuln.risk['risk_factor']:
                buf += "\tRisk factor: " + vuln.risk['risk_factor'] + "\n"
            if vuln.risk['cvss']:
                buf += "\tCVSS: " + vuln.risk['cvss'] + "\n"
            if vuln.references['nvtid']:
                buf += "\tNVTID: " + vuln.references['nvtid'] + "\n"
            if vuln.references['cve']:
                buf += "\tCVE: " + vuln.references['cve'] + "\n"
            if vuln.references['bid']:
                buf += "\tBID: " + vuln.references['bid'] + "\n"
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

class Vulnerability():
    def __init__(self):
        self.name = ''
        self.service = ''
        self.description = ''
        self.references = {'nvtid': '', 'cve': [], 'bid': []}
        self.risk = {'risk_factor': '', 'cvss': '', 'threat': ''}
    
    def __str__(self):
        return ""

def parseXML(document):
    root = etree.parse(document)
    
    vulnerabilities = {}
    # iterate over vulnerabilities
    for result in root.xpath('//result'):
        host = result.xpath('host')[0].text
        if not vulnerabilities.has_key(host):
            vulnerabilities[host] = []
            
        vuln = Vulnerability()
        
        # Summary
        vuln.description = result.xpath('description')[0].text.strip()
        vuln.name = result.xpath('nvt/name')[0].text
        vuln.host = result.xpath('host')[0].text
        vuln.service = result.xpath('port')[0].text
        
        # Risk
        vuln.risk['risk_factor'] = result.xpath('nvt/risk_factor')[0].text
        vuln.risk['cvss'] = result.xpath('nvt/cvss_base')[0].text
        vuln.risk['threat'] = result.xpath('threat')[0].text
        
        # References
        vuln.references['nvtid'] = result.xpath('nvt/@oid')[0] #oid attribute
        cve = result.xpath('nvt/cve')[0].text
        vuln.references['cve'] = cve if cve != 'NOCVE' else None
        bid = result.xpath('nvt/bid')[0].text
        vuln.references['bid'] = bid if bid != 'NOBID' else None
        
        # append vuln to vulnerabilities dictionary
        vulnerabilities[host].append(vuln)
      
    openPorts = {}
    # iterate over open ports
    for port in root.xpath('//ports/port'):
        host = port.xpath('host')[0].text
        if not openPorts.has_key(host):
            openPorts[host] = []
        
        # open port to open ports dictionary
        openPorts[host].append(port.text)
    return openPorts, __cleanupVulnerabilities(vulnerabilities)

def __cleanupVulnerabilities(vulnerabilities):
    # get rid of general information and open ports (duplicate information)
    filterOIDs = ['1.3.6.1.4.1.25623.1.0.900239',   # open tcp ports
                 '1.3.6.1.4.1.25623.1.0.103978',   # open upd ports
                 '1.3.6.1.4.1.25623.1.0.51662',    # traceroute
                 '1.3.6.1.4.1.25623.1.0.90022',    # ssh autorization
                 '1.3.6.1.4.1.25623.1.0.90011',    # smbclient not available
                 '1.3.6.1.4.1.25623.1.0.66286',    # unknown service
                 '1.3.6.1.4.1.25623.1.0.810003',   # host summary
                 '1.3.6.1.4.1.25623.1.0.19506',    # scan information
                 ]
    isNotGeneralInfo = lambda vuln: vuln.references['nvtid'] not in filterOIDs and True or False
    isNotOpenPort = lambda vuln: vuln.description != 'Open port.' and True or False
    for k in vulnerabilities:
        vulnerabilities[k] = filter(isNotGeneralInfo, vulnerabilities[k])
        vulnerabilities[k] = filter(isNotOpenPort, vulnerabilities[k])
    return vulnerabilities

if __name__ == '__main__':
    openvas_xml_report = file('../../docs/report-samples/openvas-2hosts-2012_03_24.xml', 'r')
    
    report = Report()
    report.open_ports, report.vulnerabilities = parseXML(openvas_xml_report)
    print report.printFullReport()
              
            