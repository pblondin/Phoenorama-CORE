'''
Created on Mar 17, 2012

@author: r00tme
'''
'''
from celery.task import Task
from celery.registry import tasks

#@task(name="simple_task.add")
class SimpleTask(Task):
    def run(self, x, y, **kargs):
        logger = self.get_logger()
        logger.info("Running addition task")
        return x + y;
    
tasks.register(SimpleTask)
        
def add(x, y):
logger = add.get_logger()
logger.info("Running addition task")
return x + y;'''

from celery.task import task

class SimpleTask:
    @task
    def add(self, x, y):
        logger = self.get_logger()
        logger.info("Running addition task")
        return x + y