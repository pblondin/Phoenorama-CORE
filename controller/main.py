'''
Created on Mar 17, 2012

@author: r00tme
'''

from scanner.tasks import add

if __name__ == '__main__':
    result = add.delay(2,3) #@UndefinedVariable - prevent PyDev error    
    print result.get()
    

