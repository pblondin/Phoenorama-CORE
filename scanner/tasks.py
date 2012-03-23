'''
Created on Mar 17, 2012

@author: r00tme
'''

from celery.task import task

@task(name="scanner.tasks.add")        
def add(x, y):
    logger = add.get_logger()
    logger.info("Running addition task")
    return x + y;

