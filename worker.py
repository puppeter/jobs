#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import httplib
import json
import os
import time

class worker():

    def __init__(self):
        self.command=sys.argv[1]
        self.body=sys.argv[2]
        self.receiveArray=json.loads(sys.argv[3])
        self.taskFile=sys.argv[4]
        self.operator=sys.argv[5]
        self.path=os.path.dirname(os.path.realpath(__file__))
        self.pidFilename=os.getpid()
        self.startTime=time.clock()
        self.wlog(str(self.body)+" | "+self.command+" | "+str(self.receiveArray)+" | "+self.operator+" | "+self.taskFile)

    def checkIp(self,ip):
        ip_split_list = ip.strip().split('.')  
        if 4 != len(ip_split_list):  
            return False  
        for i in range(4):  
            try:  
                ip_split_list[i] = int(ip_split_list[i])  
            except:  
                print("IP invalid:" + ipStr)  
                return False  
        for i in range(4):  
            if ip_split_list[i] <= 255 and ip_split_list[i] >= 0:  
                pass  
            else:  
                print("IP invalid:" + ipStr)  
                return False  
        return True  
    # end checkIp
    
    def dig(self,body,receiveArray):

        
        domainServer=body
        pidFilename=self.pidFilename
        for j in alarmSource:
            ip=j['ip']
            source=j['source']
            cmd='clip ssh -p null root@'+ip+' "dig '+domainServer+'" '
        
            tmp=os.popen(cmd).read()
            log="source: ip:"+ip+"("+source+") to result:"+str(tmp)+"\n"
            self.writeTmp(pidFilename,log)
            self.sendMessages(pidFilename,receiveArray)

        path=self.path+"/tmp"
        filename=path+"/"+str(pidFilename)+".tmp" 
        os.remove(filename)
    # end dig 
    
    def dvip(self,body,receiveArray):

        # check premission 
        checkRes=self.checkPremission(self.operator,receiveArray)
        if checkRes !=True:
            return False

        # end check premission

        vip=body
        pidFilename=os.getpid()
        data = {
                'ip': [vip]
        }
        import urllib2
        req = urllib2.Request('http://domainServer/index.php/dvip/dvip')
        req.add_header('Content-Type', 'application/json')

        response = urllib2.urlopen(req, json.dumps(data))
        log="result:"+response.read()+"\n"
        self.writeTmp(pidFilename,log)
    
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)"
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end dvip 

    def ping(self,body,receiveArray):
        moreIp=body[0].split("|")
            
        alarmSource=[
            {'ip':'192.168.1.1','source':'guangzhou union'},
            {'ip':'192.168.1.2','source':'hk'},
        ]
        
        pidFilename=self.pidFilename
        self.writeTmp(pidFilename,"IP 端口连通性探测报告:\n")
        if len(moreIp) > 1 :
            for j in moreIp:
                moreIpBodyArray=j.split(":")
                ip=i['ip']
                source=i['source']
                cmd='clip ssh -p null root@'+ip+' "ping -c 2 '+moreIpBodyArray[0]+'" -j'
                tmp=os.popen(cmd).readline()
                a=json.loads(tmp)
                log="source: ip:"+ip+"("+source+") to  destination: ip:"+bodyArray[0]+" result:\n"+a[1]['data']+"\n"
                self.writeTmp(pidFilename,log)
                self.writeTmp(pidFilename,"########################################################################################\n")
        else:
            bodyArray=body.split(":")       
            for i in alarmSource:
                ip=i['ip']
                source=i['source']
                cmd='clip ssh -p null root@'+ip+' "ping -c 2 '+bodyArray[0]+'" -j'
                tmp=os.popen(cmd).readline()
                a=json.loads(tmp)
                log="source: ip:"+ip+"("+source+") to  destination: ip:"+bodyArray[0]+" result:\n"+a[1]['data']+"\n"
                self.writeTmp(pidFilename,log)
        
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)" 
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end ping 

    def telnet(self,body,receiveArray):
        moreIp=body[0].split("|")
            
        alarmSource=[
            {'ip':'192.168.1.1','source':'guangzhou union'},
            {'ip':'192.168.1.2','source':'guangzhou mobile'},
        ]
        
        pidFilename=self.pidFilename
        self.writeTmp(pidFilename,"IP 端口连通性探测报告:\n")
        if len(moreIp) > 1 :
            for j in moreIp:
                moreIpBodyArray=j.split(":")
                if len(moreIpBodyArray) !=2:
                    moreIpBodyArray.append("80")

                ip=i['ip']
                source=i['source']
                cmd='clip ssh -p null root@'+ip+' "if netcat -z -w1 '+moreIpBodyArray[0]+' '+moreIpBodyArray[1]+' ;then echo "ok"; else echo "fail"; fi" -j'
                tmp=os.popen(cmd).readline()
                a=json.loads(tmp)
                log="source: ip:"+ip+"("+source+") to  destination: ip:"+bodyArray[0]+" port:"+bodyArray[1]+" result:"+a[1]['data']+"\n"
                self.writeTmp(pidFilename,log)
                self.writeTmp(pidFilename,"########################################################################################\n")
        else:
            matchHttp=body.find("http://")
            if matchHttp == 0:
                body.replace("http://","")
            bodyArray=body.split(":")
            if len(bodyArray) !=2:
                bodyArray.append("80")

            for i in alarmSource:
                ip=i['ip']
                source=i['source']
                cmd='clip ssh -p null root@'+ip+' "if netcat -z -w1 '+bodyArray[0]+' '+bodyArray[1]+' ;then echo "ok"; else echo "fail"; fi" -j'
                tmp=os.popen(cmd).readline()
                a=json.loads(tmp)
                log="source: ip:"+ip+"("+source+") to  destination: ip:"+bodyArray[0]+" port:"+bodyArray[1]+" result:"+a[1]['data']+"\n"
                self.writeTmp(pidFilename,log)
        
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)" 
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end tlenet 
    
    def uptime(self,body,receiveArray):
        # check premission 
        checkRes=self.checkPremission(self.operator,receiveArray)
        if checkRes !=True:
            return False

        # end check premission

        moreIp=body.split("|")
        pidFilename=self.pidFilename
        self.writeTmp(pidFilename,"IP 负载查看:\n")
        if len(moreIp) > 1 :
            for j in moreIp:
                ip=j

                # check register
                ipStatus=self.checkRegister(ip,receiveArray,2)
                if ipStatus !=True:
                    continue 
                # end check register

                # check ip format
                if self.checkIp(ip) != True:
                    log='invalid ip:'+ip+"\n"
                    self.writeTmp(pidFilename,log)
                    continue
                # end ip format

                cmd='clip ssh -p null root@'+ip+' "uptime" -j'
                tmp=os.popen(cmd).readline()
                a=json.loads(tmp)
                log="ip:"+ip+", uptime:"+a[1]['data']+"\n"
                self.writeTmp(pidFilename,log)
                self.writeTmp(pidFilename,"########################################################################################\n")
        else:
            ip=body

            # check register
            ipStatus=self.checkRegister(ip,receiveArray,2)
            if ipStatus !=True:
                return False 
            # end check register

            # check ip format
            if self.checkIp(ip) != True:
                log='invalid ip:'+ip+"\n"
                self.writeTmp(pidFilename,log)
                return False
            # end check ip format

            cmd='clip ssh -p null root@'+ip+' "LANG=en;uptime" -j'
            tmp=os.popen(cmd).readline()
            a=json.loads(tmp)
            log="ip:"+ip+", uptime:"+a[1]['data']+"\n"
            self.writeTmp(pidFilename,log)
        
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)"
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end uptime 
    
    def df(self,body,receiveArray):

        # check premission
        checkRes=self.checkPremission(self.operator,receiveArray)
        if checkRes !=True:
            return False
        # end check premission

        ip=body
        pidFilename=os.getpid()

        # check register
        ipStatus=self.checkRegister(ip,receiveArray,2)
        if ipStatus !=True:
            return False
        # end check register

        # check ip format
        if self.checkIp(ip) != True:
            log='invalid ip:'+ip+"\n"
            self.writeTmp(pidFilename,log)
            return False
        # end check ip format

        cmd='clip ssh -p null root@'+ip+' "LANG=en;df -h" -j'
        tmp=os.popen(cmd).readline()
        a=json.loads(tmp)
        log="ip:"+ip+", df -h:\n"+str(a[1]['data'])+"\n"
        self.writeTmp(pidFilename,log)
    
        
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)"
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end df  
    
    def fb(self,body,receiveArray):

        # check premission
        checkRes=self.checkPremission(self.operator,receiveArray)
        if checkRes !=True:
            return False
        # end check premission

        ip=body
        pidFilename=self.pidFilename

        # check register
        ipStatus=self.checkRegister(ip,receiveArray,2)
        if ipStatus !=True:
            return False
        # end check register

        # check ip format
        if self.checkIp(ip) != True:
            log='invalid ip:'+ip+"\n"
            self.writeTmp(pidFilename,log)
            return False
        # end check ip format

        
        cmd='clip ssh -p null root@'+ip+' "LANG=en;ls -lSh /data/log/* | head" -j'
        tmp=os.popen(cmd).readline().strip()
        a=json.loads(tmp)
        log="ip:"+ip+", find big file (ls -lSh /data/log/*):\n"+a[1]['data']+"\n"
        self.writeTmp(pidFilename,log)

    
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)"
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end fb  
    

    def curl(self,body,receiveArray):
        cmd='/usr/bin/curl '+body
        tmp=os.popen(cmd).readline()
        print tmp
        log="curl:"+str(tmp)+"\n"
        pidFilename=self.pidFilename
        self.writeTmp(pidFilename,log)
        useTime=time.clock()-self.startTime
        log="useTime:"+str(useTime)+"/s (平均耗时在20毫秒以下，大于20毫秒说明网络有丢包情况)"
        self.writeTmp(pidFilename,log)
        self.send(pidFilename,receiveArray)
    # end curl 
    

    def writeTmp(self,pidFilename,content):
        path=self.path+"/tmp"
        filename=path+"/"+str(pidFilename)+".tmp" 
        with open(filename,'a') as f:
            f.write(content)
        f.close()
    # end writeTmp

    def send(self,pidFilename,receiveArray):
        import commands
        path=self.path+"/tmp"
        filename=path+"/"+str(pidFilename)+".tmp" 
        (status,output)=commands.getstatusoutput('cat '+filename)
        if status == 0:
            path=self.path.replace("dispatch","")
            cmd="/usr/bin/php "+path+"receive/sender.php '"+json.dumps(receiveArray)+"' '"+str(output.replace("\n","&"))+"'"
            os.system(cmd)
        os.remove(filename)
    # end send
    

    def sendMessages(self,pidFilename,receiveArray):
        import commands
        path=self.path+"/tmp"
        filename=path+"/"+str(pidFilename)+".tmp" 
        (status,output)=commands.getstatusoutput('cat '+filename)
        if status == 0:
            path=self.path.replace("dispatch","")
            cmd="/usr/bin/php "+path+"receive/sender.php '"+json.dumps(receiveArray)+"' '"+str(output.replace("\n","&"))+"'"
            os.system(cmd)
        (status,output)=commands.getstatusoutput('> '+filename)
    # end sendMessages

    def changeTaskStatus(self):
        path=self.path.replace("dispatch","")
        taskFileRun=path+"/task/"+self.taskFile
        taskFileDone=path+"/task/"+self.taskFile.replace("run","done")
        os.rename(taskFileRun,taskFileDone)
    # end changeTaskStatus
        

    def checkPremission(self,user,receiveArray):
        if user == None:
            user='guest'

        pidFilename=self.pidFilename
        allowUser=['username']
        if user not in allowUser:
            log=" premission denied, please contact djangowang \n"
            self.writeTmp(pidFilename,log)
            self.send(pidFilename,receiveArray)
            return False
        else:
            return True
    #end checkPremission 
    
    def checkRegister(self,ip,receiveArray,action=1):
        cmd='clip cstring -i'+ip
        tmp=os.popen(cmd).readline().strip()

        if tmp == 'data empty':
            log=ip+" not reigster , please contact djangowang\n"
            self.writeTmp(self.pidFilename,log)
            self.send(self.pidFilename,receiveArray)
            return False
        else:
            log=ip+" is reigster \n"
            if action == 1:
                self.writeTmp(self.pidFilename,log)
                self.send(self.pidFilename,receiveArray)
            return True
             
    #end checkRegister

    def wlog(self,content,tag="default",level="default",logname="access.log"):

        import logging  
        # 创建一个logger  
        logger = logging.getLogger(tag)  
        logger.setLevel(logging.DEBUG)  
        ymd=time.strftime("%Y%m%d", time.localtime())  
        path=self.path+"/log/"+ymd
        if os.path.exists(path) != True:
            os.mkdir(path) 

        # 创建一个handler，用于写入日志文件  
        fh = logging.FileHandler(path+"/"+logname)  
        fh.setLevel(logging.DEBUG)  
          
        # 再创建一个handler，用于输出到控制台  
        ch = logging.StreamHandler()  
        ch.setLevel(logging.DEBUG)  
        
        # 定义handler的输出格式  
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')  
        fh.setFormatter(formatter)  
        ch.setFormatter(formatter)  
          
        # 给logger添加handler  
        logger.addHandler(fh)  
        logger.addHandler(ch)  
          
        # 记录一条日志  
        logger.info(content) 
    # end wlog

    def main(self):

        taskFile=self.taskFile.split('.')
        lockFile=self.path+"/tmp/"+str(taskFile[0])+".lock"

        # touch lock
        if os.path.exists(lockFile):
            print "lock file exists"
            sys.exit()
        with open(lockFile,'w') as f:
            f.close()
        # end touch lock

        switch = {
            # not check premission
            'telnet':lambda body,receiveArray: self.telnet(body.replace("#"+self.command+"#",""),receiveArray),
            'ping':lambda body,receiveArray: self.ping(body.replace("#"+self.command+"#",""),receiveArray),
            'cr':lambda body,receiveArray: self.checkRegister(body.replace("#"+self.command+"#",""),receiveArray), #check register
            'dig':lambda body,receiveArray: self.dig(body.replace("#"+self.command+"#",""),receiveArray), #check register
            # check premission
            'uptime':lambda body,receiveArray: self.uptime(body.replace("#"+self.command+"#",""),receiveArray),
            'dvip':lambda body,receiveArray: self.dvip(body.replace("#"+self.command+"#",""),receiveArray),
            'fb':lambda body,receiveArray: self.fb(body.replace("#"+self.command+"#",""),receiveArray),  # find big file
            'df':lambda body,receiveArray: self.df(body.replace("#"+self.command+"#",""),receiveArray),
            'curl':lambda body,receiveArray: self.curl(body.replace("#"+self.command+"#",""),receiveArray),
        }
        switch[self.command](self.body,self.receiveArray)

        os.remove(lockFile)
        self.changeTaskStatus()

    # end main

if __name__ == "__main__":
    worker=worker()
    worker.main()
 
