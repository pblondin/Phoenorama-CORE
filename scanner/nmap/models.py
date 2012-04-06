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

@author: r00tme
'''
class Nmap():
    def __init__(self):
        self.task_uuid = ''
        self.name = ''
        self.description = ''
        self.target = ''
        self.report_uuid = ''
        self.status = ''
            
    def toJSON(self):
        json = {'task_uuid' : self.task_uuid,
                'report_uuid' : self.report_uuid,
                'name': self.name,
                'description': self.description,
                'target': self.target,
                'status': self.status
                }
        return json
    
class Report():
    def __init__(self, reportUuid=''):
        self.reportUuid = reportUuid
        self.scan_info = {}
        self.results_by_host = {}
                                 
    def getHosts(self):
        return self.results_by_host.keys()
