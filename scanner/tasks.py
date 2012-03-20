'''
Created on Mar 17, 2012

@author: r00tme
'''
from celery.task import task

@task(name="simple_task.add")
def add(x, y):
    logger = add.get_logger()
    logger.info("Running addition task")
    
    return x + y;