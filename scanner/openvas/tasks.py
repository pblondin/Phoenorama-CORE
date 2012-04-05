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
Created on Mar 22, 2012

OpenVAS Task Wrapper using omp client tool interface to communicate with OpenVAS manager and scanner.
        http://www.openvas.org/install-packages.html#debian
        http://www.greenbone.net/learningcenter/remote_controlled.html

@version: 0.2
@author: r00tmac
'''
import shlex, subprocess, re, uuid, time
from StringIO import StringIO
from pymongo import Connection
from parser import parse
from celery.task import task

TOOL_PATH = '/usr/bin/omp --username "guest" --password "guest" ' # Make sure the leave a space at the end

@task(name="openvas.save")
def save(openvas, **kwargs):
    logger = save.get_logger()
    
    openvasTask = Connection().phoenorama.openvasTask
    openvasTask.insert(openvas.toJSON())
    
    logger.info("Openvas Task was successfully saved")
    

@task(name="openvas.run")
def run(openvas, **kwargs):
    '''
    Start OpenVAS task
    
    Staging:
        1. Configure scan
        2. Start scan
        3. Save report    
    '''
    logger = run.get_logger()
    
    # Configure scan
    task_uuid = __configure(openvas.target)
    logger.info("Task was successfully configured")
    
    # Update OpenVAS Task status to RUNNING
    __updateStatus(openvas, "RUNNING")
    
    # Start scan
    #TODO: Validate start_task status
    start_task = "--start-task %s" % (task_uuid)
    cmd = shlex.split(TOOL_PATH + start_task)
    report_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    logger.info("Task was successfully started")
    
    # Wait till scan is finished
    status = getStatus(report_uuid)
    while(status != "Done"):
        logger.info("Task id %s is %s" % task_uuid, status)
        time.sleep( 60 ) # 1 minute
        status = getStatus(task_uuid)
        
    # Save report
    __saveReport(report_uuid)
    logger.info("Report UUID: %s was successfully saved: %s" % report_uuid)
    
    # Update OpenVAS Task status to DONE
    __updateStatus(openvas, "DONE")
    
    return task_uuid, report_uuid

@task(name="openvas.stopTask")
def stopTask(taskUuid):
    stop_task = "<stop_task task_id='%s'/>" & taskUuid
    cmd = shlex.split(TOOL_PATH + stop_task)
    response = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    return response

@task(name="openvas.getStatus")
def getStatus(taskUuid):
    logger = getStatus.getLogger()
    
    status_task = "-G %s" % taskUuid
    cmd = shlex.split(TOOL_PATH + status_task)
    pattern = "%s(.*?)[0-9A-Fa-f]{8}" % taskUuid
    status = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    logger.info("Status: %s") % status
    status = re.search(pattern, status).group(1)
    logger.info("Status: %s") % status
    print status.strip()
    return status.strip()


#############################################
# Private methods
#############################################
def __updateStatus(openvas, status):
    openvasTask = Connection().phoenorama.openvasTask
    openvasTask.update({'_id': openvas._id}, {'status': status})
    return "Status was successfully to %s" % status

def __configure(target, **kwargs):
    '''
    Private method to configure omp client tool.

    List of config scans:
            daba56c8-73ec-11df-a475-002264764cea  Full and fast
            698f691e-7489-11df-9d8c-002264764cea  Full and fast ultimate
            708f25c4-7489-11df-8094-002264764cea  Full and very deep
            74db13d6-7489-11df-91b9-002264764cea  Full and very deep ultimate

    @requires: omp.config is already configured on the scanning nodes with credentials.
    @requires: openvassd and openvasmd deamons are running on the scanning nodes.
    '''

    # Create a temporary target
    create_target = "--xml '<create_target><name>%(uuid)s</name><hosts>%(hosts)s</hosts></create_target>'" % {"uuid": uuid.uuid4(), "hosts": target}
    cmd = shlex.split(TOOL_PATH + create_target)
    retvalue = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]

    # Get status and target_uuid #TODO: fix when status is bad (|= 201)
    # Sample: <create_target_response status="201" id="6095d2bf-9e03-4689-a717s -dc8038137004" status_text="OK, resource created"></create_target_response>
    status, target_uuid = re.search('status="(\d+)"\sid="(\S+)"', retvalue).group(1, 2)
    
    # Create a temporary task
    create_task = "--create-task --name %(uuid)s --target %(target_uuid)s --config daba56c8-73ec-11df-a475-002264764cea" % {"uuid": uuid.uuid4(), "target_uuid": target_uuid}
    cmd = shlex.split(TOOL_PATH + create_task)
    task_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
    return task_uuid
                   
def __saveReport(reportUuid):

    getReport_task = "--get-report %s" % (reportUuid)
    cmd = shlex.split(TOOL_PATH + getReport_task)
    report_xml = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]    
    #@TODO: check if output result is valid
  
    report = parse(StringIO(report_xml))    
    openvasReport = Connection().phoenorama.openvasReport
    openvasReport.insert(report.toJSON())
        
    return "Report was successfully generated and saved to DB"

def __cleanup():
    pass
