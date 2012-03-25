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
Created on Mar 17, 2012

@author: r00tme

Task dispatcher
'''

import argparse
#from scanner.tasks import add

VERSION = "0.1"

def dispatchTask(task):
    '''
    Send a distributed tasks.
    '''
    pass


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description="Send distributed scan tasks.", version=VERSION)
    argparser.add_argument("task", metavar="task", action="store",
              choices=('nmap', 'openvas', 'w3af', 'nikto'),
              help="the type of scan: nmap, openvas, w3af, nikto")
    argparser.add_argument("params", metavar="params", action="store",
              help="the parameters of the task. (Ex.: -host 192.168.103.10)")
    try:
        args = argparser.parse_args()
        
        #dispatchTask(task)
        #sendTask(args.task, args.params)

    except IOError, msg:
        argparser.error(str(msg))

