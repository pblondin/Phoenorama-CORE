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
import shlex, subprocess, re, uuid
from StringIO import StringIO
from pymongo import Connection
from parser import parse
from celery.task import task

TOOL_PATH = '/usr/bin/omp --username "guest" --password "guest" ' # Make sure the leave a space at the end

@task(name="openvas.run")
def run(target, **kwargs):
    '''
    Start OpenVAS task
    
    @postcondition: task was properly configured.
    '''
    logger = run.get_logger()
    task_uuid = __configure(target)
    
    start_task = "--start-task %s" % (task_uuid)
    cmd = shlex.split(TOOL_PATH + start_task)
    report_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
    #TODO: Validate start_task status
    
    logger.info("Report_uuid: %s" % report_uuid)
    logger.info("Task is successfully started")
    return task_uuid, report_uuid

@task(name="openvas.getStatus")
def getStatus(taskUuid):
    pass
    
@task(name="openvas.saveReport")
def saveReport(reportUuid):
    logger = saveReport.get_logger()

    getReport_task = "--get-report %s" % (reportUuid)
    cmd = shlex.split(TOOL_PATH + getReport_task)
    report_xml = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]    
    #@TODO: check if output result is valid
    
    logger.info("Retvalue: %s" % report_xml)
  
    report = parse(StringIO(report_xml))
    logger.info(report.printFullReport())
    
    openvasReport = Connection().phoenorama.openvasReport    
    openvasReport.insert(report.toJSON())
    
    return "Report was successfully generated and saved to DB"
    
@task(name="openvas.cleanup")
def cleanup():
    pass

#############################################
# Private methods
#############################################
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
    
    #logger.info("Status: %s, Target_UUID: %s" % (status, target_uuid))
    
    # Create a temporary task
    create_task = "--create-task --name %(uuid)s --target %(target_uuid)s --config daba56c8-73ec-11df-a475-002264764cea" % {"uuid": uuid.uuid4(), "target_uuid": target_uuid}
    cmd = shlex.split(TOOL_PATH + create_task)
    task_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
    #logger.info("Task_uuid: %s" % task_uuid)
    #logger.info("Task was successfully configured and is ready to start")
    return task_uuid
                   

