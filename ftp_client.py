import os,sys
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

class FTPClient:
	_prompt = "(ftp)> "

	_cmds = {'ls': 'LIST %s\r\n',
			'nls': 'NLST %s\r\n',
			'stat': 'STAT\r\n',
			'syst': 'SYST\r\n',
			'pasv': 'PASV\r\n',
			'port': 'PORT %s\r\n',	# 10,10,10,4,39,72 , where 39,72 is a port number 10056 (39*256+72)
			'quit': 'QUIT\r\n',
			'user': 'USER %s\r\n',
			'pass': 'PASS %s\r\n',
			'help': 'HELP\r\n'
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

	def _send_recv(self, msg):
		n = self._send(msg)
		if n > 0:
			res = self._recv().decode()
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
				# ~ print("port:", port)

				self._send(msg)

				# Connect and receive a message from returned address and port
				tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				tmp_sock.connect((serv, port))
				print(tmp_sock.recv(2048).decode())
				tmp_sock.close()

				# Receive information message
				print(self._recv().decode())
				return

		print("error occured:", r)

	def help(self):
		# ~ print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
		self._send_recv(self._cmds["help"])

	def connect(self, host, port):
		print(f"Connecting to {host} ", end='')
		self._sock.connect((host, port))
		print("[ OK ]")
		print(self._recv().decode())

	def disconnect(self):
		self._sock.close()

	def login(self, user, passw=""):
		print("Try login as:", user)
		if self._send_recv(self._cmds["user"] % user):
			self._send_recv(self._cmds["pass"] % passw)
		# msg = f"USER {user}\r\n"
		# n = self._send(msg)
		# if n > 0:
			# print(self._recv().decode())
			# pswd_cmd = f"PASS {passw}\r\n"
			# self._send(pswd_cmd)
			# print(self._recv().decode())

	def syst(self):
		self._send_recv(self._cmds["syst"])

	def stat(self):
		self._send_recv(self._cmds["stat"])

	def list(self, path=""):

		msg = self._cmds["ls"] % path
		self._pasv_transmission(msg)

	def nlst(self, path=""):
		self._pasv_transmission(self._cmds["nls"] % path)

	def tokenizer(self, string):
		tokens = string.split()
		cmd = tokens[0]
		try:
			arg = tokens[1]
		except IndexError:
			arg = ""
		return cmd, arg

	def loop(self):
		while True:
			try:
				inpt = input(self._prompt)
				if not inpt:
					continue

				cmd, arg = self.tokenizer(inpt)
				print("cmd:", cmd, ", arg:", arg)
				for k, v in self._cmds.items():
					if cmd == k:
						print("Finded:", k, ": ", v)
				if cmd == "exit":
					break
			except (KeyboardInterrupt, EOFError) as e:
				print("exit")
				break





if __name__ == "__main__":
	FTPClient().loop()
	# if len(sys.argv) < 2:
	# 	print("Usage %s <host>" % sys.argv[0])
	# 	sys.exit()
	#
	# host = sys.argv[1]
	#
	# ftp_cli = FTPClient()
	# ftp_cli.connect(host, 21)

	# FTPInterpretator().cmdloop()

	# while True:
	# 	inpt = input('(ftp)> ').split()
	#
	# 	if not inpt:
	# 		continue
	#
	# 	cmd = inpt[0]
	# 	if cmd == "quit" or cmd == "exit":
	# 		break

	# while True:
	# 	try:
	# 		inpt = input('> ')
	# 		tokens = inpt.split()
	#
	# 		if not tokens:
	# 			continue
	#
	# 		cmd = tokens[0]
	# 		if cmd == "quit" or cmd == "exit":
	# 			break
	# 		elif cmd == "help":
	# 			# ~ print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
	# 			# ~ ftp_cli.help()
	# 			print(ftp_cli._cmds)
	# 		elif cmd == "login":
	# 			try:
	# 				user = tokens[1]
	# 			except IndexError:
	# 				print("Usage: login <user> [passwd]")
	# 				continue
	#
	# 			try:
	# 				passwd = tokens[2]
	# 			except IndexError:
	# 				passwd = ""
	#
	# 			ftp_cli.login(user, passwd)
	#
	# 		elif cmd == "alogin":
	# 			ftp_cli.login("anonymous")
	# 		elif cmd == "userlogin":
	# 			ftp_cli.login("jake", "12345")
	#
	# 		elif cmd == "ls":
	# 			try:
	# 				s_p = tokens[1]
	# 			except IndexError:
	# 				ftp_cli.nlst()
	# 				continue
	#
	# 			if s_p == "-l":
	# 				try:
	# 					path = tokens[2]
	# 				except IndexError:
	# 					ftp_cli.list()
	# 					continue
	# 				else:
	# 					ftp_cli.list(path)
	# 			else:
	# 				ftp_cli.nlst(s_p)
	#
	# 		elif cmd == "syst":
	# 			ftp_cli.syst()
	# 		elif cmd == "stat":
	# 			ftp_cli.stat()
	# 		else:
	# 			print("Unknown Command")
	# 			# ~ msg = inpt + "\r\n"
	# 			# ~ send_msg(sock, msg)
	# 			# ~ sock.my_send(msg)
	# 			# ~ r_msg = sock.my_receive()
	# 			# ~ print(r_msg.decode())
	#
	# 		""" For LIST / or NLST /
	# 					enter to PASV mode
	# 						create new socket (sock2)
	# 						send cmd from sock1 and wait for answer
	# 						connect sock2 to returned port number 39*256+50 f.e.
	# 						close sock2
	# 						answer will return to sock1
	# 					PORT mode
	# 						listen port number (nc -lvnp 9500) or with socket
	# 						sock1 send PORT 10,10,10,4,37,28
	# 						sock1 send cmd
	# 						sock1 recv answer
	# 		"""
	#
	#
	#
	#
	# 	except (KeyboardInterrupt, EOFError) as e:
	# 		print("exit")
	# 		break
	#
	# # ~ send_msg(sock, cmds["quit"])
	# print("Disconnect")
	# ftp_cli.disconnect()
	# # ~ sock.disconnect()
