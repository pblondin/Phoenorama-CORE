'''
Created on Mar 24, 2012

@author: r00tme
'''

from scanner.simpleTask import add
from scanner.openvas import Openvas

if __name__ == '__main__':
    #result = add.delay(2, 3) #@UndefinedVariable - prevent PyDev error
    o = Openvas()
    result = o.configure.run(o, "10.0.1.0/24")
    print result.wait()