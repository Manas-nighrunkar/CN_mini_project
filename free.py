root = 'manas'
"""
def handle_GET(self, request):
        get_logger = logging.getLogger() 
        if(request.uri == ''):
            filename = ""
        elif(request.uri == '/'):
            filename = "default.html"
        else:
            url = request.uri.strip('/')   #remove / from string
            #if data uses get method the data comes in url
            regex = re.compile('[&?]')     
            if(regex.search(url) != None):
                #to separate data and uri
                filename, info = url.split('?')
                #print(info)
                l = info.split('&')
                #print(l)
            else:
                filename = url
        
        modificationtime = time.ctime(os.path.getmtime(filename))
        if(modificationtime != request.dict('If-Modified-Since')):
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
                response_body = "<h1> 404 Not Found</h1>"
        
        else:
            get_logger.info('Has Fetched not modified ' + filename)
            response_line = self.response_line(304)
            response_body = ''
            
        #to get the content type
        content_type = mimetypes.guess_type(filename)[0] or 'text/html'
        body_length = len(response_body)   
            
        extra_headers = {'Content-Type': content_type,
                        'Content-length': body_length,
                        'Last-Modified': modificationtime
                        }
            
        response_headers = self.response_headers(extra_headers)

        

        blank_line = "\r\n"
        headers =  "%s%s%s" % (
                response_line,
                response_headers,
                blank_line
                #response_body
                )
        return headers, response_body
        #--------------------------------------------------------------------------------------------------------------------------------------------
        head_logger = logging.getLogger()
        if(request.uri == '/'):
            filename = "default.html"
        else:
            filename = request.uri.strip('/')

        if os.path.exists(filename):
            head_logger.info('HEAD -> Client has fetched ' + filename)
            response_line = self.response_line(200)

            content_type = mimetypes.guess_type(filename)[0] or 'text/html'
            extra_headers = {'Content-Type': content_type,
                             'Last-Modified': modificationtime
                            }
            
            response_headers = self.response_headers(extra_headers)

        
        #returns not found error if file is not present
        else:
            response_line = self.response_line(404)
            response_headers = self.response_headers()
            #response_body = "<h1> 404 Not Found</h1>"

        blank_line = "\r\n"

        headers = "%s%s%s" % (
                response_line,
                response_headers,
                blank_line,
                )
        body = ''
        return headers, body
"""