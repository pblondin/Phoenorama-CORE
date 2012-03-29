'''
Created on Mar 24, 2012

@author: r00tme
'''

from scanner.openvas.model import Openvas
from scanner.openvas.tasks import run


if __name__ == '__main__':

    o = Openvas()
    o.name = "Basic test"
    o.description = "Openvas scan against localhost"
    o.target = "localhost"
    result = run.delay(o.target) #@UndefinedVariable - prevent PyDev error
    #o.task_uuid, o.report_uuid = result.wait()
    print result.wait()