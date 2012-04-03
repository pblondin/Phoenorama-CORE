'''
Created on Mar 29, 2012

@author: r00tmac
'''
from scanner.openvas.parser import parse
from pymongo import Connection

if __name__ == '__main__':
    openvas_xml_report = file('../docs/report-samples/openvas-2hosts-2012_03_24.xml', 'r')
    
    report = parse(openvas_xml_report)
    #print report.printFullReport()
    
    connection = Connection()
    openvasReport = connection.phoenorama.openvasReport
    
    openvasReport.insert(report.toJSON())
    
