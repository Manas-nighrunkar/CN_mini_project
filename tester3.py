import requests
from threading import *
import unittest
from time import sleep
from socket import *

port = 12345
def headerMaker(method, requestedFile):
	request = method + " " + requestedFile + " " + "HTTP/1.1" + "\r\n"
	request += "Host: 127.0.0.1/" + str(port) + "\r\n"
	request += "User-Agent: Tester v1.0" + "\r\n"
	request += "Accept: image/webp,*/*" + "\r\n"
	request += "Accept-Language: en-US,en;q=0.5" + "\r\n"
	request += "Accept-Encoding: gzip, deflate" + "\r\n"
	request += "Connection: keep-alive" + "\r\n"
	request += "Authorization: Basic YWRtaW46YWRtaW4=" + "\r\n"
	request += "\r\n"
	return request




#response = requests.get('http://127.0.0.1:12345/index3.html')
class GetRequestMaker(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(GetRequestMaker, self).__init__(*args, **kwargs)
		self.recvd = 0

	def test_simple_get(self):
		print("\nSending simple GET request")
		response = requests.get('http://127.0.0.1:12345/default.html')
		try:
			self.assertEqual(response.status_code, 200)
			print("Simple get-> PASS")
		except Exception as e:	
			print("TSimple get-> FAIL", e)

	def test_simple_get_with_auth(self):	
		print("\nSending simple GET request with Valid Auth")
		response = requests.get('http://127.0.0.1:12345/index.html', auth=requests.auth.HTTPBasicAuth('admin', 'admin'))
		try:
			self.assertEqual(response.status_code, 200)
			print("GET with Valid Auth-> PASS")
		except Exception as e:	
			print("GET with Valid Auth-> FAIL", e)
			
	def test_simple_get_with_inauth(self):	
		print("\nSending simple GET request with Invalid Auth")
		response = requests.get('http://127.0.0.1:12345/index.html', auth=requests.auth.HTTPBasicAuth('worng', 'wrong'))
		try:
			self.assertEqual(response.status_code, 401)
			print("GET with InValid Auth-> PASS")
		except Exception as e:	
			print("GET with Valid Auth-> FAIL", e)

	def test_simple_get_with_forbidden(self):
		print("\nSending simple GET request for forbidden file")
		response = requests.get('http://127.0.0.1:12345/hello.html')
		try:
			self.assertEqual(response.status_code, 403)
			print("GET with Forbidden-> PASS")
		except Exception as e:	
			print("GET with Forbidden-> FAIL", e)

	def multiple_get(self, num):
		for i in range (0, num):
			response = requests.get('http://127.0.0.1:12345/default.html')
			if response.status_code == 200:
				self.recvd += 1
	
	def test_simple_get_with_25_requests(self):
		print("\nSending multiple 25 GET requests")
		for i in range(0, 5):
			Thread(target=self.multiple_get, args=(5, )).start()
		sleep(2)
		try:
			self.assertEqual(self.recvd, 25)
			print("GET MultiClient-> PASS")
		except Exception as e:	
			print("GET MultiClient-> FAIL", e)
		self.recvd = 0
		
	def test_not_found_get(self):
		print("\nSending simple GET request for non-existing file")
		response = requests.get('http://127.0.0.1:12345/test.html')
		try:
			self.assertEqual(response.status_code, 404)
			print("GET Not Found-> PASS")
		except Exception as e:	
			print("GET Not Found-> FAIL", e)

	def test_get_bad_request(self):
		print("\nSending simple GET request with bad request URL")
		testerSocket = socket(AF_INET, SOCK_STREAM)
		testerSocket.connect(('', 12345))
		msg = headerMaker("get", "index.html")
		testerSocket.sendall(msg.encode())
		response = testerSocket.recv(1024).decode()
		testerSocket.close()
		try:	
			self.assertEqual(int(response[9:12]), 400)
			print("GET Bad Request-> PASS")
		except Exception as e:
			print("GET Bad Request-> FAIL", e)

	def test_simple_get_with_cookies(self):
		print("\nSending simple GET request with Cookies")
		response = requests.get('http://127.0.0.1:12345/default.html')
		try:
			self.assertTrue(response.headers["Set-Cookie"])
			print("GET Cookies-> PASS")
		except Exception as e:	
			print("GET Cookies-> FAIL", e)

	def test_simple_post(self):
		print("\nSending simple POST request")
		response = requests.post('http://127.0.0.1:12345/default.html', data="Test data for Simple Post")
		try:
			self.assertEqual(response.status_code, 200)
			print("POST simple-> PASS")
		except Exception as e:	
			print("POST simple-> FAIL", e)	

	def test_post_bad_request(self):
		print("\nSending simple POST request with bad request URL")
		testerSocket = socket(AF_INET, SOCK_STREAM)
		testerSocket.connect(('', 12345))
		msg = headerMaker("post", "index.html")
		testerSocket.sendall(msg.encode())
		response = testerSocket.recv(1024).decode()
		testerSocket.close()
		try:
			#print(response)
			self.assertEqual(int(response[9:12]), 400)
			print("POST Bad Request-> PASS")
		except Exception as e:
			print("POST Bad Request-> FAIL", e)
	
	def multiple_post(self, num):
		for i in range (0, num):
			response = requests.post('http://127.0.0.1:12345/default.html', data="Test data for multiple post")
			if response.status_code == 200:
				self.recvd += 1
	
	def test_simple_post_with_25_requests(self):
		print("\nSending multiple 25 POST requests")
		for i in range(0, 5):
			Thread(target=self.multiple_post, args=(5, )).start()
		sleep(1)
		try:
			self.assertEqual(self.recvd, 25)
			print("POST multiClient-> PASS")
		except Exception as e:	
			print("POST multiClient-> FAIL", e)
		self.recvd = 0

#here replace filename with some non_existing fileName
	def test_simple_put_non_existing(self):
		print("\nSending simple PUT request for non existing file")
		response = requests.put('http://127.0.0.1:12345/put_data.txt', data="Test data for Simple PUT")
		try:
			self.assertEqual(response.status_code, 200)
			print("PUT simple-> PASS")
		except Exception as e:	
			print("PUT simple-> FAIL", e)

	def test_simple_post_with_forbidden(self):
		print("\nSending simple POST request for forbidden file")
		response = requests.post('http://127.0.0.1:12345/hello.html', data="Test data for POST")
		try:
			self.assertEqual(response.status_code, 403)
			print("PUT Forbidden-> PASS")
		except Exception as e:	
			print("PUT Forbidden-> FAIL", e)

	def test_simple_put_existing(self):
		print("\nSending simple PUT request for existing file")
		response = requests.put('http://127.0.0.1:12345/put_data.txt', data="Test data for Simple PUT")
		try:
			self.assertEqual(response.status_code, 200)
			print("PUT Existing-> PASS")
		except Exception as e:	
			print("PUT Existing-> PASSy", e)

	def multiple_put(self, num):
		for i in range (0, num):
			response = requests.post('http://127.0.0.1:12345/data.txt', data="Test data for multiple PUT")
			if response.status_code == 200:
				self.recvd += 1

	def test_simple_put_with_25_requests(self):
		print("\nSending multiple 25 PUT requests")
		for i in range(0, 5):
			Thread(target=self.multiple_put, args=(5, )).start()
		sleep(1)
		try:
			self.assertEqual(self.recvd, 25)
			print("PUT MultiClient-> PASS")
		except Exception as e:	
			print("PUT MultiClient-> FAIL", e)
		self.recvd = 0

	def test_put_bad_request(self):
		print("\nSending simple PUT request with bad request URL")
		testerSocket = socket(AF_INET, SOCK_STREAM)
		testerSocket.connect(('', 12345))
		msg = headerMaker("put", "test_put.txt")
		testerSocket.sendall(msg.encode())
		response = testerSocket.recv(1024).decode()
		testerSocket.close()
		try:
			#print(response)
			self.assertEqual(int(response[9:12]), 400)
			print("PUT Bad Request-> PASS")
		except Exception as e:
			print("PUT Bad Request-> FAIL", e)

	def test_simple_put_with_forbidden(self):
		print("\nSending simple PUT request for forbidden file")
		response = requests.put('http://127.0.0.1:12345/hello.html')
		try:
			self.assertEqual(response.status_code, 403)
			print("The simple PUT for forbidden file working correctly")
		except Exception as e:	
			print("The simple PUT for forbidden file not working correctly", e)

	def test_simple_head(self):
		print("\nSending simple HEAD request")
		response = requests.head('http://127.0.0.1:12345/default.html')
		try:
			self.assertEqual(response.status_code, 200)
			print("The simple HEAD working correctly")
		except Exception as e:	
			print("The simple HEAD not working correctly", e)

	def test_simple_head_with_auth(self):	
		print("\nSending simple HEAD request with Valid Auth")
		response = requests.head('http://127.0.0.1:12345/index.html', auth=requests.auth.HTTPBasicAuth('admin', 'admin'))
		try:
			self.assertEqual(response.status_code, 200)
			print("The simple HEAD working correctly with Valid Auth")
		except Exception as e:	
			print("The simple HeAD not working correctly with Valid Auth", e)
			
	def test_simple_head_with_inauth(self):	
		print("\nSending simple HEAD request with Invalid Auth")
		response = requests.head('http://127.0.0.1:12345/index.html', auth=requests.auth.HTTPBasicAuth('temp', 'temp'))
		try:
			self.assertEqual(response.status_code, 401)
			print("The simple HEAD working correctly with Invalid Auth")
		except Exception as e:	
			print("The simple HEAD not working correctly with Invalid Auth", e)

	def multiple_head(self, num):
		for i in range (0, num):
			response = requests.head('http://127.0.0.1:12345/default.html')
			if response.status_code == 200:
				self.recvd += 1
	
	def test_simple_head_with_25_requests(self):
		print("\nSending multiple 25 HEAD requests")
		for i in range(0, 5):
			Thread(target=self.multiple_head, args=(5, )).start()
		sleep(1)
		try:
			self.assertEqual(self.recvd, 25)
			print("The simple HEAD with 25 requests working correctly")
		except Exception as e:	
			print("The simple HEAD with 25 requests not working correctly", e)
		self.recvd = 0
		
	def test_not_found_head(self):
		print("\nSending simple HEAD request for non-existing file")
		response = requests.get('http://127.0.0.1:12345/not_exists.html')
		try:
			self.assertEqual(response.status_code, 404)
			print("The simple HEAD request for non-existing file working correctly")
		except Exception as e:	
			print("The simple HEAD request for non-existing file not working correctly", e)

	def test_head_bad_request(self):
		print("\nSending simple HEAD request with bad request URL")
		testerSocket = socket(AF_INET, SOCK_STREAM)
		testerSocket.connect(('', 12345))
		msg = headerMaker("head", "index.html")
		testerSocket.sendall(msg.encode())
		response = testerSocket.recv(1024).decode()
		testerSocket.close()
		try:	
			self.assertEqual(int(response[9:12]), 400)
			print("The simple HEAD request for bad request URL working correctly")
		except Exception as e:
			print("The simple HEAD request for bad request URL not working correctly", e)

	def test_simple_delete_non_existing(self):
		print("\nSending simple DELETE request for non existing file")
		response = requests.delete('http://127.0.0.1:12345/delete_test.txt')
		try:
			self.assertEqual(response.status_code, 404)
			print("The simple DELETE request for non existing file working correctly")
		except Exception as e:	
			print("The simple DELETE request for non existing file not working correctly", e)
	
	def test_simple_delete_existing(self):
		print("\nSending simple DELETE request for existing file")
		response = requests.delete('http://127.0.0.1:12345/delete_test.txt')
		try:
			self.assertEqual(response.status_code, 404)
			print("The simple DELETE request for existing file working correctly")
		except Exception as e:	
			print("The simple DELETE request for existing file not working correctly", e)		

	def test_delete_bad_request(self):
		print("\nSending simple DELETE request with bad request URL")
		testerSocket = socket(AF_INET, SOCK_STREAM)
		testerSocket.connect(('', 12345))
		msg = headerMaker("delete", "test_put.txt")
		testerSocket.sendall(msg.encode())
		response = testerSocket.recv(1024).decode()
		testerSocket.close()
		try:
			#print(response)
			self.assertEqual(int(response[9:12]), 400)
			print("The simple DELETE request for bad request URL working correctly")
		except Exception as e:
			print("The simple DELETE request for bad request URL not working correctly", e)
	
	
if __name__ == '__main__':
	unittest.main()
