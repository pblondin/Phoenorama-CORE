'''
Created on Mar 24, 2012

@author: r00tme
'''

from scanner.openvas.models import Openvas
from scanner.openvas.tasks import run, save
#from scanner.nmap.tasks import run

def testOpenVas():
    o = Openvas()
    o.name = "Basic test"
    o.description = "Openvas scan against localhost"
    #o.target = "localhost"
    o.target = "www.rdexperts.com"
    o.status = "NEW"
    save.delay(o) #@UndefinedVariable
    
    run.delay(o) #@UndefinedVariable
    
    
    #task_uuid, report_uuid = run.delay(o).wait() #@UndefinedVariable - prevent PyDev error
    #o.task_uuid, o.report_uuid = result.wait()
    #print result.wait()
    #print task_uuid
        
    #result = saveReport.delay("e41c81ea-24e4-4981-a0d0-1b5d9839fbb8") #@UndefinedVariable
    #print result.wait()
        
def testNmap():
    result = run.delay("www.rdexperts.com") #@UndefinedVariable
    print result.wait()


if __name__ == '__main__':

    testOpenVas()
    #testNmap()
    