'''
Created on Mar 24, 2012

@author: r00tme
'''

from scanner.simpleTask import add
from scanner.openvas import Openvas

if __name__ == '__main__':
    #result = add.delay(2, 3) #@UndefinedVariable - prevent PyDev error
    o = Openvas()
    print o.tool
    result = o.configure.delay(o, "127.0.0.1")
    print result.get()