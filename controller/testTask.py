'''
Created on Mar 24, 2012

@author: r00tme
'''

from scanner.simpleTask import add

if __name__ == '__main__':
    result = add.delay(2, 3) #@UndefinedVariable - prevent PyDev error    
    print result.get()