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
import shlex, subprocess, re, csv
from celery.task import task

class Openvas():
    '''
    Run OpenVAS scan using OMP client (openvas-cli)
       
    Example: 
        OpenVAS-Client -T nbe -qx 127.0.0.1 9390 <user> <pass> /root/openvas/target /var/www/openvas/results.nbe
    '''
    HOST = '127.0.0.1'
    PORT = 9390
    USER = 'user'
    PASSWORD = 'password'
    FORMAT = 'nbe'
    PATH = './results/'
    
    def __init__(self, task_id):
        #self.task = OpenVASTask.objects.get(pk=task_id) # Get result object
        self.tool = '/usr/bin/OpenVAS-Client ' # Make sure the leave a space at the end
        self.config = '-T {format} -qx {host} {port} {user} {password} {target} {result}'
    
    @task(name="scanner.openvas.configure")
    def configure(self, targetFile, nbeFile):
        '''
        Configure OpenVAS tool by setting the appropriate config information.
        '''
        self.config = self.config.format(format=self.FORMAT, 
                                         host=self.HOST, 
                                         port=self.PORT, 
                                         user=self.USER, 
                                         password=self.PASSWORD,
                                         target=self.PATH + str(targetFile), 
                                         result=self.PATH + str(nbeFile))

        # Write the targetFile
        f = open(self.PATH + str(targetFile), 'w')
        f.write(self.task.project.target)
        f.close()
    
    @task(name="scanner.openvas.run")
    def run(self):
        '''
        Define how to run OpenVAS and convert the results.
        
        1. Start a process to run OpenVAS.
        2. Parse the NBE result file.
        3. Add results to the task.
        '''
        cmd = shlex.split(self.tool + self.config)
        subprocess.call(cmd)
        self.__parse(self.task.nbeFile)
               
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
