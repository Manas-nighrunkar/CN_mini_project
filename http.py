import socket
import os
import mimetypes
import time
import _thread
import sys
import re
import logging
import random
from configparser import ConfigParser
import signal

class TCP_Server:
    
    server_logger = logging.getLogger() 
    CLIENTS = []
    def __init__(self, host = '127.0.0.1', port = 8888):
        #address for our server
        self.host = host
        #port for our server
        self.port = port

    #def start(self):
        #create a socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #bind the socket to given address and port
        self.s.bind((self.host, self.port))

        #start listening for connections on given port
        self.s.listen(200)
        #self.server_logger.debug("Server Listening at" + str(self.s.getsockname()[0]) + str(self.s.getsockname()[1]))
        print("Server Listening at", self.s.getsockname())
        while True:
            try:
                conn, addr = self.s.accept()
            except:
                self.server_logger.debug("STOPPED")
                sys.exit()

            self.CLIENTS.append(conn)
            #self.server_logger.debug("connected by", addr)
            print("connected by", addr)
            _thread.start_new_thread(self.CLIENT_THREAD, (conn,addr))


    def CLIENT_THREAD(self, conn, addr):
        while True:
            try:
                BUFF_SIZE = 4096
                data = b''
                while True:
                        part = conn.recv(BUFF_SIZE)
                        data += part
                        if len(part) < BUFF_SIZE:
                            break
                data_str = data.decode()
                if data_str:
                    #function to handle data response
                    headers, body = self.handle_request(data_str)
                    #message = bytes(headers,'utf-8')
                    self.SEND(headers, body, conn)
                else:
                    self.remove(conn)
            except Exception as e:
                self.server_logger.warning(e)
                break
            
    def SEND(self, message_headers, message_body, conn):
        for clients in self.CLIENTS:
            if clients == conn:
                try:
                    #headers are string so encode it t bytes
                    headers = bytes(message_headers,'utf-8')
                    conn.sendall(headers)
                    #body is bytes beacuse file opened in binary mode
                    conn.sendall(message_body)
                    conn.close()
                except:
                    clients.close()
                    self.remove(clients)
    
    def remove(self,conn):
        if conn in self.CLIENTS:
            self.CLIENTS.remove(conn)

################################################################################################################################# 
class HTTP_Server(TCP_Server):
    random_number = random.randint(10000,99999)
    #body_length = None
    #current time
    gmttime = time.strftime("%a, %d %b %Y %X GMT", time.gmtime())
    headers = {
            'Date': gmttime,
            'Server': 'Manas_Server',
            'Content-length': '0',
            'Connection': 'Close',
            'Content-Type': 'text/html',
            'Last-Modified': gmttime,
            'Content-Encoding': "text",
            }
    #status_code = httplib.responses
    status_code = {
            200: 'OK',
            404: 'NOT FOUND',
            501: 'Not Implemented',
            400: 'Bad Request',
            204: 'No Content',
            201: 'Created',
            304: 'Not Modified'
            }

################################################################################################################################# 

    #handles tje request GET /index.html HTTP 1.1
    def handle_request(self, data):

        #create an instance of request
        request = HTTP_Request(data)
        
        try:
            #to check which method is needed
            handler = getattr(self, 'handle_%s' % request.http_method)
        except AttributeError:
            handler = self.HTTP_501_handler
        
        #handler of methods(get, post)
        headers, body = handler(request)
        return headers, body
   

#################################################################################################################################            
    def response_line(self, status_code):
        #Returns response line
        reason = self.status_code[status_code]
        return "HTTP/1.1 %s %s\r\n" % (status_code, reason)

#################################################################################################################################        
    def response_headers(self, extra_headers = None):
        #returns headers
        #make a local copy of headers
        headers_copy = self.headers.copy() 
        if extra_headers:
            headers_copy.update(extra_headers)
        headers = ""

        #print all header such as server name, content-type
        for h in headers_copy:
            headers += "%s: %s\r\n" % (h, headers_copy[h])
        return headers
    
#####################################################################################################################
    def handle_GET(self, request):
        #print(request.dict)
        get_logger = logging.getLogger() 
        if(request.uri == ''):
            filename = ""
        elif(request.uri == request.root):
            filename = "default.html"
        else:
            url = request.uri.strip('/')   #remove / from string
            #if data uses get method the data comes in url
            regex = re.compile('[&?]')     
            if(regex.search(url) != None):
                #to separate data and uri
                filename, info = url.split('?')
                #print(info)
                #l = info.split('&')
                #print(l)
            else:
                filename = url
        
        #name, extension = os.path.splitext(filename)
        encoding = (request.dict['Accept-Encoding']).split(", ")
        for i in range (len(encoding)):
            if(encoding[i] == 'gzip'):
                encoding[i] = 'gz'
            if(os.path.exists(filename + "." + encoding[i])):
                filename = filename + "." + encoding[i]
                if(encoding[i] != 'gz'):
                    finalextension = encoding[i]
                else:
                    finalextension = 'gzip'
                break

        #if file exists calculate its modification time
        if os.path.exists(filename):
            modificationtime = time.ctime(os.path.getmtime(filename))
        else:
            modificationtime = self.gmttime

        #firstly check if request headers have if modified since headers then only compare
        #if not use normal method
        finalextension = 'text'
        if 'If-Modified-Since' in request.dict.keys():

            #if file is modified send a new resonse containing file body
            if(modificationtime != request.dict['If-Modified-Since']):
                if os.path.exists(filename):
                    get_logger.info('GET -> Client has fetched ' + filename)
                    response_line = self.response_line(200)
                    
                    #open file in binary mode so it is in bytes
                    with open(filename,'rb') as f:
                        response_body = f.read()                
                
                # returns not found error if file is not present
                else:
                    response_line = self.response_line(404)
                    get_logger.info('GET -> Client has requested for not available file ' + filename ) 
                    response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode()
            
            #if the file is not modified simply send 304
            else:
                get_logger.info('GET -> Has Fetched not modified ' + filename)
                response_line = self.response_line(304)
                response_body = ''

        #if modified since headers is missing    
        else:
            if os.path.exists(filename):
                get_logger.info('GET -> Client has fetched ' + filename)
                response_line = self.response_line(200)
                #open file in binary mode so it is in bytes
                with open(filename,'rb') as f:
                    response_body = f.read() 
                

            # returns not found error if file is not present
            else:
                response_line = self.response_line(404)
                response_headers = self.response_headers()
                get_logger.info('GET -> Client has requested for not available file ' + filename )
                response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode()
            
        #to get the content type
        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
        body_length = len(response_body)
        if 'Cookie' not in request.dict.keys():
            cookie_value = str(self.random_number)
            cookie = 'SessionId' + '=' + cookie_value
            get_logger.info("GET -> cookie sent: " + cookie)  
            extra_headers = {'Content-Type': content_type,
                            'Content-length': body_length,
                            'Last-Modified': modificationtime,
                            'Set-Cookie': cookie,
                            'Content-Encoding': finalextension,
                            }
        else:
            extra_headers = {'Content-Type': content_type,
                            'Content-length': body_length,
                            'Last-Modified': modificationtime,
                            'Content-Encoding': finalextension,
                            }

            
        response_headers = self.response_headers(extra_headers)

        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                )
        return headers, response_body

#################################################################################################################################
    def handle_POST(self, request):
        #print(request.dict)
        post_logger = logging.getLogger()
        if(request.uri == request.root):
            filename = "default.html"
        else:
            filename = request.uri.strip('/')   #remove / from string
        
        #if requested file is present log the infor and send the file body
        if os.path.exists(filename):
            post_logger.info('POST -> Client has accessed ' + filename + ' and the post info is - ' + '\n' + request.info)
            response_line = self.response_line(200)     
            
            with open(filename,'rb') as f:
                response_body = f.read()

        # returns not found error if file is not present
        else:
            response_line = self.response_line(404)
            response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode()
        
        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
        body_length = len(response_body)
        if 'Cookie' not in request.dict.keys():
            cookie_value = str(self.random_number)
            cookie = 'SessionId' + '=' + cookie_value
            post_logger.info("POST -> cookie sent: " + cookie)
            extra_headers = {'Content-Type': content_type,
                             'Content-length': body_length,
                            'Set-Cookie': cookie,
                            }
        else:
            extra_headers = {'Content-Type': content_type,
                             'Content-length': body_length,
                            }

        response_headers = self.response_headers(extra_headers)
        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                )
        
        return headers, response_body

#################################################################################################################################
    def handle_PUT(self, request):
        #print(request.dict)
        put_logger = logging.getLogger()
        if(request.uri):
            filename = request.uri.strip('/')   #remove / from string
        else:
            filename = ""
        if os.path.exists(filename):
            put_logger.info('PUT -> Client has written in ' + filename + ' - ' + '\n' + request.info)
            response_line = self.response_line(200)
        else:
            put_logger.info('PUT -> Client has created and written in ' + filename + ' - ' + '\n' + request.info)
            response_line = self.response_line(201)

        with open(filename,"w") as f:
            f.write(request.info)

        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
        response_body = "<h1> SUCCESS </h1>".encode()
         
        body_length = len(response_body)
        if 'Cookie' not in request.dict.keys():
            cookie_value = str(self.random_number)
            cookie = 'SessionId' + '=' + cookie_value
            put_logger.info("PUT -> cookie sent: " + cookie)
            extra_headers = {'Content-Type': content_type,
                            'Content-length': body_length,
                            'Set-Cookie': cookie,
                            }

        else:
            extra_headers = {'Content-Type': content_type,
                            'Content-length': body_length,
                            }

        response_headers = self.response_headers(extra_headers)

        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                )
        return headers, response_body

#################################################################################################################################
    def handle_DELETE(self, request):
        delete_logger = logging.getLogger()
        if(request.uri):
            filename = request.uri.strip('/')   #remove / from string
        else:
            filename = ""
        
        if os.path.exists(filename):
            delete_logger.info('DELETE -> Client has deleted ' + filename)
            response_line = self.response_line(200)
            try:            
                os.remove(filename)
                response_body = "<h1> SUCCESS </h1>".encode()
            except:
                response_body = "<h1> Permission Error </h1>".encode()
        else:
            response_line = self.response_line(404)
            response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode() 
            delete_logger.info('DELETE -> Client has requested to delete not available ' + filename)

        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
        body_length = len(response_body)
        if 'Cookie' not in request.dict.keys():
            cookie_value = str(self.random_number)
            cookie = 'SessionId' + '=' + cookie_value
            delete_logger.info("DELETE -> cookie sent: " + cookie)
            extra_headers = {'Content-Type': content_type,
                             'Content-length': body_length,
                            'Set-Cookie': cookie,
                            }
        else:
            extra_headers = {'Content-Type': content_type,
                             'Content-length': body_length,
                            }

        response_headers = self.response_headers(extra_headers)

        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                )
        return headers, response_body

#################################################################################################################################
    def handle_HEAD(self, request):
        #print(request.dict)
        head_logger = logging.getLogger() 
        if(request.uri == ''):
            filename = ""
        elif(request.uri == request.root):
            filename = "default.html"
        else:
            filename = request.uri.strip('/')   #remove / from string
             
        #the whole method is same as get just without body
        if os.path.exists(filename):
            modificationtime = time.ctime(os.path.getmtime(filename))
        else:
            modificationtime = self.gmttime
        if 'If-Modified-Since' in request.dict.keys():
            if(modificationtime != request.dict['If-Modified-Since']):
                if os.path.exists(filename):
                    head_logger.info('HEAD -> Client has fetched ' + filename)
                    response_line = self.response_line(200)
                
                # returns not found error if file is not present
                else:
                    response_line = self.response_line(404)
                    head_logger.warning('HEAD -> Client has requested for not available file ' + filename ) 
                    response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode()
 
            else:
                head_logger.info('HEAD -> Has Fetched not modified ' + filename)
                response_line = self.response_line(304)
                response_body = ''
            
        else:
            if os.path.exists(filename):
                head_logger.info('HEAD -> Client has fetched ' + filename)
                response_line = self.response_line(200)
                 

            # returns not found error if file is not present
            else:
                response_line = self.response_line(404)
                response_headers = self.response_headers()
                head_logger.info('HEAD -> Client has requested for not available file ' + filename )
                response_body = "<h1> ERROR 404 NOT FOUND </h1>".encode()

        #to get the content type
        content_type = mimetypes.guess_type(filename)[0] or 'text/html'   
        if 'Cookie' not in request.dict.keys():
            cookie_value = str(self.random_number)
            cookie = 'SessionId' + '=' + cookie_value
            head_logger.info("HEAD -> cookie sent: " + cookie)
            extra_headers = {'Content-Type': content_type,
                            'Last-Modified': modificationtime,
                            'Set-Cookie': cookie,
                            }
        else:
            extra_headers = {'Content-Type': content_type,
                            'Last-Modified': modificationtime,
                            }
            
        response_headers = self.response_headers(extra_headers)
        response_body = ''

        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                )
        return headers, response_body  

#################################################################################################################################
    #function for not implemented methods   
    def HTTP_501_handler(self, request):
        response_line = self.response_line(status_code = 501)

        blank_line = "\r\n"

        response_body = "<h1> ERROR: NOT IMPLEMENTED </h1>".encode()
        content_length = len(response_body)
        extra_headers = {'Content-length': content_length
                        }
        response_headers = self.response_headers(extra_headers)
        
        headers = "%s%s%s" % (
                response_line,
                response_headers,
                blank_line,
                )
        return headers, response_body

#################################################################################################################################
#handles the request line eg. GET /index.html HTTP/1.1
class HTTP_Request():
    def __init__(self, data):
        self.http_method = None
        self.uri = ''
        self.http_version = '1.1'
        self.headers = {}
        self.request_lines = []
        self.dict = {}
        self.info = ""
        configur = ConfigParser() 
        configur.read('config.ini')
        self.root = configur.get('My_Settings','RootDirectory')
        self.log_file_name = configur.get('My_Settings','LogFileName')
        #parse the data into lines
        print(data)
        self.parse(data)
        #Log file
        LOG_FORMAT = "%(levelname)s %(asctime)s - %(message)s"
        logging.basicConfig(filename = self.log_file_name,
                            level = logging.DEBUG,
                            format = LOG_FORMAT)
        

#################################################################################################################################
    def parse(self, data):
        lines = data.split("\r\n")
        #length_line = len(lines)
        #we only require first line
        #request_line = lines[0]
        self.parse_request_line(lines)
    
#################################################################################################################################
    #parse the first line into words
    def parse_request_line(self, request_line):
        first_line = request_line[0]
        words = str(first_line).split(" ")
        
        if len(words) < 2:
            return
        #http version if given otherwise default = 1.1
        if len(words) > 2:
            self.http_version = words[2]

        self.http_method = words[0]
        self.uri = words[1]
        self.uri = self.root + self.uri
        if(self.http_method == 'GET' or self.http_method == 'HEAD' or self.http_method == 'DELETE'):
            self.handle_get_headers(request_line)
        elif(self.http_method == 'POST' or self.http_method == 'PUT'):
            self.handle_post_headers(request_line)
        
#################################################################################################################################
    def handle_get_headers(self, request_line):

            for i in range (1, len(request_line)-2):
                word = request_line[i].split(': ')
                self.dict[word[0]] = word[1] 
            #print(self.dict['If-Modified-Since'])

#################################################################################################################################
    def handle_post_headers(self, request_line):
        i = 1
        while(request_line[i] != ''):
            word = request_line[i].split(': ')
            self.dict[word[0]] = word[1]
            i += 1
        i += 1
        while(i != len(request_line)):
            self.info += request_line[i]
            if i != len(request_line) - 1:
                self.info += "\n"
            i += 1
        
#################################################################################################################################
if __name__ == '__main__':
    server = HTTP_Server()
    #server.start()
