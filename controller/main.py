'''
Created on Mar 17, 2012

@author: r00tme
'''
from scanner import tasks

if __name__ == '__main__':
    result = tasks.add(2,3)
    #result = add.apply_async(agrs=[10, 10], countdown=3)
    print result
    
    #result = send_task("worker.simple_task.add", [2, 3]);
    #print result.get()
    
    print "test"