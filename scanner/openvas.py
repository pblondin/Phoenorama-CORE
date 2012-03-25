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
        self.tool = '/usr/bin/omp --username "guest" --password "guest" -v ' # Make sure the leave a space at the end
        #self.task = OpenVASTask.objects.get(pk=task_id) # Get result object
    
    @task(name="scanner.openvas.configure")
    def configure(self, target, **kwargs):
        '''
        Configure omp client tool.
        
        @requires: omp.config is already configured on the scanning nodes with credentials.
        @requires: openvassd and openvasmd deamons are running on the scanning nodes.
        '''
        logger = self.get_logger()
        
        # Create a temporary target
        create_target = "--xml '<create_target><name>%(name)s</name><hosts>%(hosts)s</hosts></create_target>'" % {"name": uuid.uuid4(), "hosts": target}
        cmd = shlex.split(self.tool + create_target)
        logger.info(cmd)
        target_uuid = subprocess.call(cmd)
        return target_uuid

        
    @task(name="scanner.openvas.getStatus")
    def getStatus(self, taskUuid):
        pass
    
    @task(name="scanner.openvas.run")
    def run(self):
        '''
        Define how to run OpenVAS and convert the results.
        
        @postcondition: task was properly configured.
        
        1. Start a process to run OpenVAS.
        2. Parse the NBE result file.
        3. Add results to the task.
        '''
        cmd = shlex.split(self.tool + self.config)
        retcode = subprocess.call(cmd)
        self.__parse(self.task.nbeFile)
        
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
