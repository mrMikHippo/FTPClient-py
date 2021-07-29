import os
import sys
import socket
import functools
import time


class MySocket:
	
	def __init__(self, sock=None):
		if sock is None:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			self.sock = sock
		
	def connect(self, host, port):
		print(f"Connecting to {host} ", end='')
		self.sock.connect((host, port))
		print("[ OK ]")
	
	def disconnect(self):
		self.sock.close()
		
	def send(self, msg):
		totalsent = 0
		while totalsent < len(msg):
			sent = self.sock.send(msg[totalsent:].encode())
			if sent == 0:
				raise RuntimeError("socket connection broken")
			totalsent = totalsent + sent
		return totalsent


	def recv(self):
		chunks = []
		bytes_recd = 0
		# ~ MSGLEN = 2048
		msg = self.sock.recv(2048)
		return msg
		
		
		
		# ~ while bytes_recd < MSGLEN:
			# ~ chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
			# ~ if chunk == b'':
				# ~ raise RuntimeError("socket connection broken")
			# ~ chunks.append(chunk)
			# ~ bytes_recd = bytes_recd + len(chunk)
		# ~ return b''.join(chunks)

def send_msg(sock, msg):
	print("Send:", msg)
	n = sock.send(msg)
	print(n, "bytes")
	if n > 0:
		print("Recv:")
		recv = sock.recv().decode()
		print(recv)
		return recv
		
	print("Not sended `\_O_/'")
	return None

def connect_to_socket(serv, port):
	rc = os.fork()
	
	if rc == 0:
		# Child
		# ~ print('I am child, PID: ', os.getpid())
		print(f"Server {serv}:{port}\n")
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((serv, port))
		print(sock.recv(2048).decode())
		sock.close()
		os._exit(0)
	elif rc > 0:
		pass
		# ~ print('I am parent,PID:', os.getpid())		
	else:
		print('Child process creation failed!!')
	

def simplex_pasv(sock, msg):
	print("Simplex Recieve")
	# Enter to PASV mode
	answ = send_msg(sock, 'PASV\r\n').split()
	# 227 Entering Passive Mode (10,10,10,4,39,71).
	if answ[0] == "227":
		serv_port = answ[-1].strip('().').split(',')
		serv = ".".join(serv_port[:4])
		# Port number a*256+b ... f.e. 39*256+71
		port = functools.reduce(lambda a, b: int(a)*256+int(b), serv_port[4:])
		# ~ print("port:", port)		
		
		sock.send(msg)
		
		# Connect and receive a message from returned address and port
		sock_recv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_recv.connect((serv, port))
		print(sock_recv.recv(2048).decode())
		sock_recv.close()

		# Receive information message
		print(sock.recv().decode())					
		print(sock.recv().decode())
	

class FTPClient:
	
	_cmds = {'ls': 'LIST %s\r\n',
			'nls': 'NLST %s\r\n',
			'stat': 'STAT\r\n',
			'syst': 'SYST\r\n',
			'pasv': 'PASV\r\n',
			'port': 'PORT %s\r\n',	# 10,10,10,4,39,72 , where 39,72 is a port number 10056 (39*256+72)
			'quit': 'QUIT\r\n',
			'user': 'USER %s\r\n',
			'pass': 'PASS %s\r\n'
			}

	def __init__(self, sock=None):		
		if sock is None:
			self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			self._sock = sock
		self._sock.settimeout(1)
	
	def _send(self, msg):		
		return self._sock.send(msg.encode())
	
	def _recv(self):
		chunks = []
		
		while True:
			try:
				chunk = self._sock.recv(2048)
				chunks.append(chunk)
				# ~ print("Add chunk:", chunk)
				if chunk == b'':
					print("Chunk is empty")
					break
				
			except socket.timeout:
				# ~ print("E: Timed out")
				break
		
		return b''.join(chunks)
	
	
	def help(self):
		print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
		
	def connect(self, host, port):
		print(f"Connecting to {host} ", end='')
		self._sock.connect((host, port))
		print("[ OK ]")
		# ~ print(self._sock.CMSG_LEN)
		print(self._recv())
	
	def disconnect(self):
		self._sock.close()
			
	def login(self, user, passw=""):
		print("Try login as:", user)
		msg = f"USER {user}\r\n"
		n = self._send(msg)
		if n > 0:
			print(self._recv().decode())
			pswd_cmd = f"PASS {passw}\r\n"
			self._send(pswd_cmd)
			print(self._recv().decode())
		
	def syst(self):
		n = self._send(self._cmds["syst"])
		if n > 0:
			print(self._recv().decode())
	
	def stat(self):
		n = self._send(self._cmds["stat"])
		if n > 0:
			print(self._recv().decode())
		
	def list(self, path):
	
		# Enter to PASV mode
		n = self._send(self._cmds["pasv"])
		if n > 0:
			r = self._recv().decode()
			print(r)
			# 227 Entering Passive Mode (10,10,10,4,39,71).
			answ = r.split()
			if answ[0] == "227":
				serv_port = answ[-1].strip('().').split(',')
				serv = ".".join(serv_port[:4])
				# Port number a*256+b ... f.e. 39*256+71
				port = functools.reduce(lambda a, b: int(a)*256+int(b), serv_port[4:])
				# ~ print("port:", port)		
				
				self._send(self._cmds["ls"] % path)
				
				# Connect and receive a message from returned address and port
				tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				tmp_sock.connect((serv, port))
				print(tmp_sock.recv(2048).decode())
				tmp_sock.close()

				# Receive information message
				print(self._recv().decode())					
	
	# ~ def nlst(self, path):
		
	
	
if __name__ == "__main__":
	
	if len(sys.argv) < 2:
		print("Usage %s <host>" % sys.argv[0])
		sys.exit()
	
	host = sys.argv[1]

	# ~ sock = MySocket()
	# ~ sock.connect(host, 21)
	# ~ print(sock.recv().decode())
	
	cmds = {'ls': 'LIST %s\r\n',
			'nls': 'NLST %s\r\n',
			'stat': 'STAT\r\n',
			'syst': 'SYST\r\n',
			'pasv': 'PASV\r\n',
			'port': 'PORT %s\r\n',	# 10,10,10,4,39,72 , where 39,72 is a port number 10056 (39*256+72)
			'quit': 'QUIT\r\n',
			'user': 'USER %s\r\n',
			'pass': 'PASS %s\r\n'
			}
	users = {"anon": {
				"user": 'USER anonymous\r\n', 
				"pass": 'PASS\r\n'},
			 "ftpuser": {
				"user": 'USER ftpuser\r\n', 
				"pass": 'PASS 12345\r\n'},
			}

	ftp_cli = FTPClient()
	ftp_cli.connect(host, 21)
	
	while True:
		try:
			inpt = input('> ')
			tokens = inpt.split()
			
			if not tokens:
				continue

			cmd = tokens[0]
			if cmd == "quit" or cmd == "exit":
				break
			elif cmd == "help":
				print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")				
				continue
			elif cmd == "login":
				try:
					user = tokens[1]
				except:
					print("Usage: login <user> [passwd]")
					continue
				
				try:
					passwd = tokens[2]
				except:
					passwd = ""
				
				ftp_cli.login(user, passwd)
				
				
			elif cmd == "alogin":
				print("Login as anonymous..")
				ftp_cli.login("anonymous")
			elif cmd == "userlogin":
				ftp_cli.login("jake", "12345")
			

			elif cmd == "ls":
				try:
					path = tokens[1]
				except IndexError:
					path = "*"
				
				ftp_cli.list(path)						
			elif cmd == "nls":
				try:
					path = tokens[1]
				except IndexError:
					path = "*"
				# ~ ftp_cli.nlst(path)	
			elif cmd == "syst":
				ftp_cli.syst()				
			elif cmd == "stat":
				ftp_cli.stat()
			else:
				print("Unknown Command")
				# ~ msg = inpt + "\r\n"
				# ~ send_msg(sock, msg)
				# ~ sock.my_send(msg)
				# ~ r_msg = sock.my_receive()
				# ~ print(r_msg.decode())
				
			""" For LIST / or NLST /
						enter to PASV mode
							create new socket (sock2) 
							send cmd from sock1 and wait for answer
							connect sock2 to returned port number 39*256+50 f.e.
							close sock2
							answer will return to sock1
						PORT mode
							listen port number (nc -lvnp 9500) or with socket
							sock1 send PORT 10,10,10,4,37,28
							sock1 send cmd
							sock1 recv answer
			"""
			
							
						

		except (KeyboardInterrupt, EOFError) as e:
			print("exit")	
			break

	# ~ send_msg(sock, cmds["quit"])
	print("Disconnect")
	ftp_cli.disconnect()
	# ~ sock.disconnect()

