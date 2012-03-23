#!/usr/bin/env python
import pika
import sys, argparse
from socket import gethostname;

# Send distributed scans.
#   1. nmap <host>
#   2. openvas <host>
#   3. w3af <url>
#   4. nikto <url>

VERSION="0.1"

def sendTask(task, host):
   '''
   Send a distributed scan tasks.
   '''
   connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
   channel = connection.channel()

   # Declare queue 
   channel.queue_declare(queue='task_queue', durable=True)

   # Message to send
   message = task + ':' + host

   # Exchanging the task
   channel.basic_publish(exchange='',
                         routing_key='task_queue',
                         body=message,
                         properties=pika.BasicProperties(
                            delivery_mode = 2, # make message persistent
                         ))

   print ' [%s] Sent %r' % (gethostname(), message,)

   # Close connection
   connection.close()


if __name__ == '__main__':
   argparser = argparse.ArgumentParser(description="Send distributed scan tasks.", version=VERSION)
   argparser.add_argument("task", metavar="task", action="store",
			  choices = ('nmap', 'openvas', 'w3af', 'nikto'), 
			  help = "the type of scan: nmap, openvas, w3af, nikto")
   argparser.add_argument("params", metavar="params", action="store",
			  help = "the parameters of the task. (Ex.: -host 192.168.103.10)")

   try:
      args = argparser.parse_args()
      sendTask(args.task, args.params)

   except IOError, msg:
      argparser.error(str(msg))

