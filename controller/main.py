'''
Created on Mar 17, 2012

@author: r00tme
'''

#from scanner.tasks import SimpleTask
#from celery.execute import send_task
#from scanner.tasks import SimpleTask

from celery.task import task

@task
def add(x, y):
    logger = add.get_logger()
    logger.info("Running addition task")
    return x + y

if __name__ == '__main__':
    #result = SimpleTask.add.delay(2,3)
    #result = tasks.add(2,3)
    result = add.delay(2,3)
    #result = tasks.relay.add(2,3)
    #result = add.apply_async(agrs=[10, 10], countdown=3)
    print result
    #result = SimpleTask.delay(2,3)
    
    #result = send_task("tasks.add", [2, 3]);
    print result.get()
    
    print "test"




