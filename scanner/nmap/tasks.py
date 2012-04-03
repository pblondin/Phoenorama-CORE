#######
#
# Copyright (C) 2012 Phoenorama.org All Rights Reserved.
# Author: Philippe Blondin <pblondin@phoenorama.org>>
#
# This file is part of the Phoenorama program.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#
#######

'''
Created on Apr 2, 2012

Nmap Task Wrapper

@version: 0.1
@author: r00tmac
'''

import shlex, subprocess, re, uuid
from celery.task import task

TOOL_PATH = '/usr/local/bin/nmap-5.51 -PN -sT -sV -sC -A -T4 -oX - ' # Make sure the leave a space at the end

@task(name="nmap.run")
def run(target, **kwargs):
    '''
    Start nmap task
    
    @postcondition: 
    '''
    logger = run.get_logger()
    
    start_task = "%s" % (target)
    cmd = shlex.split(TOOL_PATH + start_task)
    report_xml = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
    #TODO: Validate start_task status
    
    logger.info("Report_xml %s" % report_xml)
    logger.info("Task is successfully started")
    return report_xml

@task(name="nmap.getStatus")
def getStatus(taskUuid):
    pass
    
@task(name="nmap.saveReport")
def saveReport(reportUuid):
    pass

@task(name="nmap.cleanup")
def cleanup():
    pass

#############################################
# Private methods
#############################################
