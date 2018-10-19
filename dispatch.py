#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import httplib
import json
import os
import threading 

class dispatch:

    def __init__(self):
        self.path=os.path.dirname(os.path.realpath(__file__))
    
    def runWorker(self):
        path=self.path.replace("dispatch",'')
        cmd='cd '+path+'/task/; ls -l *.run 2> /dev/null | awk \'{print $NF}\''
        tmp=os.popen(cmd).readlines()
        if len(tmp) == 0:
            return False

        for i in tmp:
            taskFile=i.strip()
            fileAddr=path+'/task/'+taskFile
            file=open(fileAddr)
            fileContent=file.readline()
            a=json.loads(fileContent)
            cmd=path+"dispatch/worker.py "+a['command']+" '"+a['body']+"' '"+json.dumps(a['receiveArray'])+"' '"+taskFile+"' '"+a['operator']+"' &"
            print cmd
            cmd=str(cmd)
            os.system(cmd)
    
if __name__ == "__main__":
    dispatch=dispatch()
    dispatch.runWorker()
