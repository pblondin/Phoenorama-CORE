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

import shlex, subprocess, re, uuid, time
from StringIO import StringIO
from pymongo import Connection
from parser import parse
from celery.task import task

TOOL_PATH = '/usr/local/bin/nmap-5.51 -PN -sT -sV -sC -A -T4 -oX - ' # Make sure the leave a space at the end

@task(name="nmap.save")
def save(nmap, **kwargs):
    logger = save.get_logger()
    
    nampTask = Connection().phoenorama.nmapTask
    nampTask.insert(nmap.toJSON())
    
    logger.info("Nmap Task was successfully saved")

@task(name="nmap.run")
def run(target, **kwargs):
    '''
    Start nmap task
    '''
    logger = run.get_logger()
    
    start_task = "%s" % (target)
    cmd = shlex.split(TOOL_PATH + start_task)
    report_xml = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
    #TODO: Validate start_task status
    
    # Save report
    report = parse(StringIO(report_xml))    
    nmapReport = Connection().phoenorama.nmapReport
    nmapReport.insert(report.toJSON())

    logger.info("Report id: %s was successfully generated and saved to DB" % report.report_uuid)
    return report_xml

@task(name="nmap.getStatus")
def getStatus(taskUuid):
    pass


@task(name="nmap.cleanup")
def cleanup():
    pass

#############################################
# Private methods
#############################################

def __updateNmap(nmap, fieldsToUpdate):
    nmapTask = Connection().phoenorama.nmapTask
    nmapTask.update({'task_uuid': nmap.task_uuid}, {'$set' : fieldsToUpdate})
    return "Nmap was successfully updated"








