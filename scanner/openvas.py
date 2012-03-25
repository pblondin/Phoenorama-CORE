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

@author: r00tmac
'''
import shlex, subprocess, re, csv, uuid
from celery.task import task

class Openvas():
    '''
    OpenVAS wrapper using omp client tool interface to communicate with OpenVAS manager and scanner.
        http://www.openvas.org/install-packages.html#debian
        http://www.greenbone.net/learningcenter/remote_controlled.html

    @version: 0.1
    '''

    def __init__(self):
        self.tool = '/usr/bin/omp --username "guest" --password "guest" ' # Make sure the leave a space at the end
        self.target_uuid = ''
        self.task_uuid = ''
        self.report_uuid = ''
        self.status = ''

    @task(name="scanner.openvas.configure")
    def configure(self, target, **kwargs):
        '''
        Configure omp client tool.

        List of config scans:
                daba56c8-73ec-11df-a475-002264764cea  Full and fast
                698f691e-7489-11df-9d8c-002264764cea  Full and fast ultimate
                708f25c4-7489-11df-8094-002264764cea  Full and very deep
                74db13d6-7489-11df-91b9-002264764cea  Full and very deep ultimate

        @requires: omp.config is already configured on the scanning nodes with credentials.
        @requires: openvassd and openvasmd deamons are running on the scanning nodes.
        '''
        logger = self.configure.get_logger()

        # Create a temporary target
        create_target = "--xml '<create_target><name>%(uuid)s</name><hosts>%(hosts)s</hosts></create_target>'" % {"uuid": uuid.uuid4(), "hosts": target}
        cmd = shlex.split(self.tool + create_target)
        retvalue = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]

        # Get status and target_uuid #TODO: fix when status is bad (|= 201)
        # Sample: <create_target_response status="201" id="6095d2bf-9e03-4689-a717s -dc8038137004" status_text="OK, resource created"></create_target_response>
        self.status, self.target_uuid = re.search('status="(\d+)"\sid="(\S+)"', retvalue).group(1, 2)
        
        logger.info("Status: %s, Target_UUID: %s" % (self.status, self.target_uuid))
        
        # Create a temporary task
        create_task = "--create-task --name %(uuid)s --target %(target_uuid)s --config daba56c8-73ec-11df-a475-002264764cea" % {"uuid": uuid.uuid4(), "target_uuid": self.target_uuid}
        cmd = shlex.split(self.tool + create_task)
        self.task_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
        
        logger.info("Task_uuid: %s" % self.task_uuid)
        return "Task was successfully configured and is ready to start"
        
    @task(name="scanner.openvas.getStatus")
    def getStatus(self, taskUuid):
        pass
    
    @task(name="scanner.openvas.run")
    def run(self):
        '''
        Start OpenVAS task
        
        @postcondition: task was properly configured.

        '''
        logger = self.run.get_logger()
        start_task = "--start-task %s" % (self.task_uuid)
        cmd = shlex.split(self.tool + start_task)
        self.report_uuid = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    
        
        #TODO: Validate start_task status
        
        logger.info("Report_uuid: %s" % self.report_uuid)
        return "Task is successfully started"

        
    @task(name="scanner.openvas.getReport")
    def getReport(self):
        pass
        
    @task(name="scanner.openvas.cleanup")
    def cleanup(self):
        pass
               
    def __parse(self, nbe_file):
        '''
        A private method for parsing a NBE file (OpenVAS, Nessus) and convert into our RESULT model.         
        Every result is added to the task.
        ''' 
        try:
            whole_file = csv.reader(open(nbe_file, 'rb'), delimiter='|')
            for row in whole_file:
                if len(row) == 0:
                    pass
                else:
                    if row[0] == "results": # Make sure it's actually a result (evade timestamps)
                        '''my_result = Result()
                        
                        if len(row) == 4: # Open port
                            my_result.title = "Open port"
                            my_result.summary = "The port %s is open." % (row[3])
                            my_result.target = row[2]
                            my_result.service = row[3]
                            my_result.description = "The port %s is open. Make sure it conforms with your corporate security policy." % (row[3])
                        
                        if len(row) > 4: # Normal vulnerability (NVT)
                            my_result.nvt = NVT.objects.get(oid=row[4])
                            my_result.title = my_result.nvt.name
                            my_result.summary = my_result.nvt.summary                            
                            my_result.target = row[2]
                            my_result.service = row[3]
                            my_result.description = row[6]
                            my_result.risk_factor = self.__getrisklevel(row[5], row[6])                            
                        
                        my_result.save() # Serialize the result object
                        self.task.results.add(my_result) # Add the result to the task
                        '''
                                
        except IOError, msg:
            print (str(msg))

    #############################################
    # Private methods for parsing
    #############################################
    def __getrisklevel(self, risk, value):
        result = 'u' # Unknown        
        if risk == "Security Hole":
            result = 'c' # Critical
        elif risk == "Security Warning":
            match = re.search("Risk factor\W+(\w+)", value)
            if match:
                tmpmatch = match.group(1).lower().strip()
                if tmpmatch == "high":
                    result = 'h' # High
                if tmpmatch == "medium":
                    result = 'm' # Medium
                else:
                    result = "l" # Low
        elif risk == "Log Message" or risk == "Security Note":
            result = 'i' # Info
        return result
