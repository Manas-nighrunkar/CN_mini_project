import socket
import os
import mimetypes

class TCP_Server:
    def __init__(self, host = '127.0.0.1', port = 8888):
        #address for our server
        self.host = host
        #port for our server
        self.port = port

    def start(self):
        #create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #bind the socket to given address and port
        s.bind((self.host, self.port))

        #start listening for connections on given port
        s.listen(100)

        print("Server Listening at", s.getsockname())

        #infinite loop till keyboard interrupt
        while True:

            #accept the incoming new connection
            conn, addr = s.accept()

            #addr is address of client
            print("connected by", addr)

            #recieve the data sent by client(1024 bytes)
            data = conn.recv(1024)
            
            #while recving data it comes in byte format in pythin3 
            #so it needs to be converted to str before doing operations
            data_str = data.decode('utf-8')
            
            #function to handle data response
            request = self.handle_request(data_str)

            #send the data back to client
            response = bytes(request,'utf-8')
            conn.sendall(response)
            
            #close the connection
            conn.close()

class HTTP_Server(TCP_Server):
    headers = {
            'Server': 'Manas_Server',
            'Content-Type': 'text/html',
            }
    #status_code = httplib.responses
    status_code = {
            200: 'OK',
            404: 'NOT FOUND',
            501: 'Not Implemented'
            }
    
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
        response = handler(request)
        return response
   
       
    def response_line(self, status_code):
        #Returns response line
        reason = self.status_code[status_code]
        return "HTTP/1.1 %s %s\r\n" % (status_code, reason)
        
    def response_headers(self, extra_headers = None):
        #returns headers
        #make a local copy of headers
        headers_copy = self.headers.copy() 
        if extra_headers:
            headers_copy.update(extra_headers)
        headers = ""

        #print all header such as server name, content-type
        for h in self.headers:
            headers += "%s: %s\r\n" % (h, self.headers[h])
        return headers
    
    #handles get method
    def handle_GET(self, request):
        filename = request.uri.strip('/')   #remove / from string
        
        if os.path.exists(filename):
            print ('Client has fetched ' + filename)
            response_line = self.response_line(200)

            content_type = mimetypes.guess_type(filename)[0] or 'text/html'
            extra_headers = {'Content-Type': content_type}
            
            response_headers = self.response_headers(extra_headers)

            with open(filename) as f:
                response_body = f.read()
        
        #returns not found error if file is not present
        else:
            response_line = self.response_line(404)
            response_headers = self.response_headers()
            response_body = "<h1> 404 Not Found</h1>"

        blank_line = "\r\n"

        return "%s%s%s%s" % (
                response_line,
                response_headers,
                blank_line,
                response_body
                )

    #tempoary function for not implemented methods   
    def HTTP_501_handler(self, request):
        response_line = self.response_line(status_code = 501)

        response_headers = self.response_headers()

        blank_line = "\r\n"

        response_body = "<h1> ERROR: 501 Not Implemented......Please check the method called</h1>"
        
        return "%s%s%s%s" % (
                response_line,
                response_headers,
                blank_line,
                response_body
                )
    

#handles the request line eg. GET /index.html HTTP/1.1
class HTTP_Request():
    def __init__(self, data):
        self.http_method = None
        self.uri = None
        self.http_version = '1.1'
        self.headers = {}
        
        #parse the data into lines
        self.parse(data)

    def parse(self, data):
        lines = data.split("\r\n")
        
        #we only require firse line
        request_line = lines[0]
        self.parse_request_line(request_line)
    
    #parse the first line into words
    def parse_request_line(self, request_line):
        words = str(request_line).split(" ")
        
        if len(words) < 2:
            return
        
        self.http_method = words[0]
        self.uri = words[1]
        
        #http version if given otherwise default = 1.1
        if len(words) > 2:
            self.http_version = words[2]


if __name__ == '__main__':
    server = HTTP_Server()
    server.start()
