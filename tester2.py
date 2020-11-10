import http.client
from socket import *
from threading import *
import getopt
import sys
import math
from time import sleep
import unittest

port = 0
getNum = 0
postNum = 0
putNum = 0
deleteNum = 0
headNum = 0
getFile = ""
putFile = ""
deleteFile = ""
postFile = ""
headFile = ""
#h - help
#p - server port number
#G - get requests to send
#P - post
#U - put
#D - delete
#H - head

try:
    opts, args = getopt.getopt(sys.argv[1:], "hp:G:P:U:D:H:", ["getFile=", "putFile=", "postFile=", "deleteFile=", "headFile="])
except getopt.GetoptError as e:
    print(e)
    sys.exit(2)
for o, a in opts:
    if o == "-h":
        print ("python tester.py Options\nOptions:\n-p [server port] \n-G [# of get requests] \n-P [# of post requests] \n-U [# of put requests] \n-D [# of delete requests] \n-H [# of head requests] \n--getFile [req file] \n--postFile [post data file] \n--deleteFile [file to delete] \n--headFile [req file] \n--putFile [file to put]")
        sys.exit()
    elif o == "-p":
        port = int(a)
    elif o == "-G":
        getNum = int(a)
    elif o == "-P":
        postNum = int(a)
    elif o == "-U":
        putNum = int(a)
    elif o == "-D":
        deleteNum = int(a)
    elif o == "-H":
        headNum = int(a)
    elif o == "--getFile":
        getFile = a
    elif o == "--putFile":
        putFile = a
    elif o == "--postFile":
        postFile = a
    elif o == "--deleteFile":
        deleteFile = a
    elif o == "--headFile":
        headFile = a
    else:
        print("Enter correct arguments.")
        sys.exit()
        
httpVersion = "HTTP/1.1"

#c = number of requests to send per thread
#threads = number of simultaneous threads to send n requests in a loop
testcase = unittest.TestCase()

def headerMaker(method, requestedFile):
    request = method + " " + requestedFile + " " + httpVersion + "\r\n"
    request += "Host: 127.0.0.1/" + str(port) + "\r\n"
    request += "User-Agent: Tester v1.0" + "\r\n"
    request += "Accept: image/webp,*/*" + "\r\n"
    request += "Accept-Language: en-US,en;q=0.5" + "\r\n"
    request += "Accept-Encoding: gzip, deflate" + "\r\n"
    request += "Connection: keep-alive" + "\r\n"
    request += "Referer: " + "\r\n"
    request += "If-Modified-Since: " + "\r\n"
    request += "Cache-Control: max-age=0" + "\r\n"
    request += "\r\n"
    return request

def getRequestMaker(file, c):
    for i in range (0, c): 
        conn = http.client.HTTPConnection('127.0.0.1', 8888)
        #headers = {}
        #passList = []
        headers = {'Authorization': 'Basic YWRtaW46YWRtaW4='}
        conn.request("GET", getFile , headers=headers)
        response = conn.getresponse()
        #print("Status: {} and reason: {}".format(response.status, response.reason))
        status = response.status
        reason = response.reason
        try:
            testcase.assertEqual(status, 200)
            testcase.assertEqual(reason, "OK")
            print("pass")
            #passList.append("pass")
        except:
            #passList.append("fail")
            print("fail")
        unittest.main()
        #headers = response.getheaders()
        #print("Headers: {}".format(headers))

def postRequestMaker(file, c):
    for i in range (0, c):
        conn = http.client.HTTPConnection('127.0.0.1', 8888)
        #headers = {}
        #passList = []
        data = "POST data from tester"
        headers = {'Authorization': 'Basic YWRtaW46YWRtaW4='}
        conn.request("POST", postFile, data , headers=headers)
        response = conn.getresponse()
        #print("Status: {} and reason: {}".format(response.status, response.reason))
        status = response.status
        reason = response.reason
        try:
            testcase.assertEqual(status, 200)
            testcase.assertEqual(reason, "OK")
            print("pass")
            #passList.append("pass")
        except:
            #passList.append("fail")
            print("fail")
        #headers = response.getheaders()
        #print("Headers: {}".format(headers))

def putRequestMaker(file, c):
    for i in range (0, c):
        conn = http.client.HTTPConnection('127.0.0.1', 8888)
        #headers = {}
        #passList = []
        data = "PUT data from tester"
        headers = {'Authorization': 'Basic YWRtaW46YWRtaW4='}
        conn.request("PUT", putFile, data , headers=headers)
        response = conn.getresponse()
        #print("Status: {} and reason: {}".format(response.status, response.reason))
        status = response.status
        reason = response.reason
        try:
            testcase.assertEqual(status, 200)
            testcase.assertEqual(reason, "OK")
            print("pass")
            #passList.append("pass")
        except:
            #passList.append("fail")
            print("fail")
        #headers = response.getheaders()
        #print("Headers: {}".format(headers))

def deleteRequestMaker(file, c):
    for i in range (0, c):
        testerSocket = socket(AF_INET, SOCK_STREAM)
        try:
            testerSocket.connect(('', port))
        except Exception as e:
            print(e)
            sys.exit()    
        request = headerMaker("DELETE", file)
        testerSocket.send(request.encode())
        sleep(0.5)
        print(testerSocket.recv(4096).decode(), "\n")

def headRequestMaker(file, c):
    for i in range (0, c):
        testerSocket = socket(AF_INET, SOCK_STREAM)
        try:
            testerSocket.connect(('', port))
        except Exception as e:
            print(e)
            sys.exit()
        request = headerMaker("HEAD", file)
        testerSocket.send(request.encode())
        sleep(0.5)
        print(testerSocket.recv(4096).decode(), "\n")

getThreads = math.ceil(0.2*getNum)
try:
    getc = math.ceil(getNum/getThreads)
except ZeroDivisionError:
    getc = 0
postThreads = math.ceil(0.2*postNum)
try:
    postc = math.ceil(postNum/postThreads)
except ZeroDivisionError:
    postc = 0

putThreads = math.ceil(0.2*putNum)
try:
    putc = math.ceil(putNum/putThreads)
except ZeroDivisionError:
    putc = 0

deleteThreads = math.ceil(0.2*deleteNum)
try:
    deletec = math.ceil(deleteNum/deleteThreads)
except ZeroDivisionError:
    deletec = 0

headThreads = math.ceil(0.2*headNum)
try:
    headc = math.ceil(headNum/headThreads)
except ZeroDivisionError:
    headc = 0

totalThreads = getThreads + postThreads + putThreads + deleteThreads + headThreads
for i in range(0, totalThreads):
    while getThreads != 0:
        Thread(target= getRequestMaker, args= (getFile, min(getNum, getc))).start()
        getThreads -= 1
        getNum -= min(getNum, getc)   
    while postThreads != 0:
        Thread(target= postRequestMaker, args= (postFile, min(postNum, postc))).start()
        postThreads -= 1
        postNum -= min(postNum, postc)
    while putThreads != 0:
        Thread(target= putRequestMaker, args= (putFile, min(putNum, putc))).start()
        putThreads -= 1
        putNum -= min(putNum, putc)
    while deleteThreads != 0:
        Thread(target= deleteRequestMaker, args= (deleteFile, min(deleteNum, deletec))).start()
        deleteThreads -= 1
        deleteNum -= min(deleteNum, deletec)
    while headThreads != 0:
        Thread(target= headRequestMaker, args= (headFile, min(headNum, headc))).start()
        headThreads -= 1
        headNum -= min(headNum, headc)




    
