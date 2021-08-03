import os,sys
import socket
import functools
import time
import getpass

class FTPClient:
	_prompt = "(ftp)> "
	_host = None
	_timeout = 1

	_cmds = {'list': 'LIST %s\r\n',
			'nlst': 'NLST %s\r\n',
			'stat': 'STAT\r\n',
			'syst': 'SYST\r\n',
			'pasv': 'PASV\r\n',
			'port': 'PORT %s\r\n',	# 10,10,10,4,39,72 , where 39,72 is a port number 10056 (39*256+72)
			'quit': 'QUIT\r\n',
			'user': 'USER %s\r\n',
			'pass': 'PASS %s\r\n',
			'help': 'HELP\r\n'
			}

	def __init__(self, host=None):
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		
		self.set_timeout(self._timeout)
		if host:
			self._host = host
	
	def set_timeout(self, timeout, verbose=False):
		if verbose:
			print("Set timeout to", timeout)
		self._timeout = timeout
		self._sock.settimeout(self._timeout)

	def connect(self, host=None):		
		if host:
			self._host = host

		self._sock.connect((self._host, 21))
		
		print("Connected to %s" % self._host)
		print(self._recv())

	def disconnect(self):
		self._send_recv(self._cmds["quit"])
		self._sock.close()

	def _send(self, msg, verbose=False):
		if verbose:
			print("[_send] msg=", msg)
		return self._sock.send(msg.encode())

	def _recv(self, end_recv="", verbose=False):
		chunks = []

		while True:
			try:
				chunk = self._sock.recv(2048)
				chunks.append(chunk)
				if verbose:
					print("[ {} ] Add chunk: {}".format(sys._getframe().f_code.co_name, chunk))
				if chunk == b'':
					# ~ print("Chunk is empty")
					if verbose:
						print("[ {} ] Chunk is empty.".format(sys._getframe().f_code.co_name))
					break

			except socket.timeout:
				# ~ print("E: Timed out")
				if verbose:
					print("[ {} ] Exit: Timed out.".format(sys._getframe().f_code.co_name))
				break

		return b''.join(chunks).decode().strip()

	def _send_recv(self, msg, end_recv="", verbose=False):
		if verbose:
			print("[ {} ] msg=".format(sys._getframe().f_code.co_name, msg))
		n = self._send(msg)
		if n > 0:
			res = self._recv(end_recv, verbose)
			if verbose:
				print("[ {} ] res={}".format(sys._getframe().f_code.co_name, res))
			else:
				print(res)
			return res

	def _pasv_transmission(self, msg):
		# Enter to PASV mode
		r = self._send_recv(self._cmds["pasv"])
		if r:
			# 227 Entering Passive Mode (10,10,10,4,39,71).
			answ = r.split()
			if answ[0] == "227":
				serv_port = answ[-1].strip('().').split(',')
				serv = ".".join(serv_port[:4])
				# Port number a*256+b ... f.e. 39*256+71
				port = functools.reduce(lambda a, b: int(a)*256+int(b), serv_port[4:])
				# ~ print(serv + ":" + str(port))

				# Connect and receive a message from returned address and port
				tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				tmp_sock.connect((serv, port))
				self._send(msg)
				print(tmp_sock.recv(2048).decode())
				tmp_sock.close()

				# Receive information message
				print(self._recv())
				return

		print("error occured:", r)

	def help(self):
		# ~ print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
		self._send_recv(self._cmds["help"])

	def user(self, user):
		self._send_recv(self._cmds["user"] % user)
		
		pswd = getpass.getpass('Password:')
		
		res = self._send_recv(self._cmds["pass"] % pswd)
	
		if not res:
			while True:
				res = self._recv(verbose=True)
				if res:
					print(res)					
					break

		if not res.split()[0] == "230":
			print("Login failed.")
			return

	def syst(self):
		self._send_recv(self._cmds["syst"])

	def stat(self):
		res = self._send_recv(self._cmds["stat"], verbose=True)
		# ~ if res:
			# ~ while True:
				# ~ if res == "211 End of status":
					# ~ break
				

	def list(self, path=""):

		msg = self._cmds["list"] % path
		self._pasv_transmission(msg)

	def nlst(self, path=""):
		self._pasv_transmission(self._cmds["nlst"] % path)

	def _tokenizer(self, string):
		tokens = string.split()
		cmd = tokens[0]
		try:
			arg = tokens[1]
		except IndexError:
			arg = ""
		return cmd, arg

	def loop(self):
		
		user = input("Name: ")
		
		self.user(user)
		
		while True:
			try:
				inpt = input(self._prompt)
				if not inpt:
					continue

				cmd, arg = self._tokenizer(inpt)
				for k, v in self._cmds.items():
					if cmd == k:						
						method = None
						try:
							# Get class method
							method = getattr(self, k)
						except AttributeError:
							print("Class `{}` does not implement `{}`".format(self.__class__.__name__, k))
							break
						# Check arguments count
						if method.__code__.co_argcount > 1: 
							method(arg)
						else:
							method()
						break
							
				if cmd == "exit":
					break
			except (KeyboardInterrupt, EOFError) as e:
				print("exit")
				break





if __name__ == "__main__":
	
	if len(sys.argv) < 2:
		print("Usage %s <host>" % sys.argv[0])
		sys.exit()
	
	host = sys.argv[1]
	
	ftpclient = FTPClient(host)
	ftpclient.connect()
	
	
	ftpclient.loop()
	
	ftpclient.disconnect()
