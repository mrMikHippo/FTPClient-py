import os,sys
import socket
from functools import reduce
import time
import getpass
from threading import Thread
import inspect

class FTPClient:
	_prompt = "(ftp)> "
	_passive_mode = False

	_cmds = {
			'acct': 'ACCT\r\n', # Account information.
			'adat': 'ADAT\r\n',	# Authentication/Security Data
			# ~ 'auth': 'AUTH\r\n', # Authentication/Security Mechanism
			'avbl': 'AVBL\r\n', # Get the available space
			# ~ 'ccc': 'CCC\r\n', 	# Clear Command Channel
			'cdup': 'CDUP\r\n', # Change to Parent Directory.
			# ~ 'csid': 'CSID\r\n', # Client / Server Identification
			'cwd': 'CWD %s\r\n',	# Change working directory.
			'dele': 'DELE %s\r\n',	# Delete file.
# ~ 'dsiz': 'DSIZ\r\n',	# Get the directory size
			# ~ 'eprt': 'EPRT\r\n',	# Specifies an extended address and port to which the server should connect.
			# ~ 'epsv': 'EPSV\r\n',	# Enter extended passive mode.
			'feat': 'FEAT\r\n',	# Get the feature list implemented by the server.
			
			'help': 'HELP\r\n',	# Returns usage documentation on a command if specified, else a general help document is returned.
			'host': 'HOST\r\n',	# Identify desired virtual host on server, by name.
			# ~ 'lang': 'LANG\r\n',	# Language Negotiation
			'list': 'LIST %s\r\n',	# Returns information of a file or directory if specified, else information of the current working directory is returned.
			# ~ 'lprt': 'LPRT\r\n',	# Specifies a long address and port to which the server should connect.
			# ~ 'lpsv': 'LPSV\r\n',	# Enter long passive mode.
# ~ 'mdtm': 'MDTM\r\n',	# Return the last-modified time of a specified file.
			# ~ 'mcft': 'MFCT\r\n',	# Modify the creation time of a file.
			# ~ 'mff': 'MFF\r\n',	# Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
			# ~ 'mfmt': 'MFMT\r\n',	# Modify the last modification time of a file.
			# ~ 'mic': 'MIC\r\n',	# Integrity Protected Command
			'mkd': 'MKD %s\r\n',	# Make directory.
			# ~ 'mlsd': 'MLSD\r\n',	# Lists the contents of a directory if a directory is named.
			# ~ 'mlst': 'MLST\r\n',	# Provides data about exactly the object named on its command line, and no others.
# ~ 'mode': 'MODE\r\n',	# Sets the transfer mode (Stream, Block, or Compressed).
			'nlst': 'NLST %s\r\n',	# Returns a list of file names in a specified directory.
			'noop': 'NOOP\r\n',	# No operation (dummy packet; used mostly on keepalives).
			# ~ 'opts': 'OPTS\r\n',	# Select options for a feature (for example OPTS UTF8 ON).
			'pass': 'PASS %s\r\n',	# Authentication password.
			'pasv': 'PASV\r\n',	# Enter passive mode.
			# ~ 'pbsz': 'PBSZ\r\n',	# Protection Buffer Size
			'port': 'PORT %s\r\n',	# Specifies an address and port to which the server should connect.
			# ~ 'prot': 'PROT\r\n',	# Data Channel Protection Level.
			'pwd': 'PWD\r\n',	# Print working directory. Returns the current directory of the host.
			'quit': 'QUIT\r\n',	# Disconnect.
			# ~ 'rein': 'REIN\r\n',	# Re initializes the connection.
			# ~ 'rest': 'REST\r\n',	# Restart transfer from the specified point.
			'retr': 'RETR %s\r\n',	# Retrieve a copy of the file
			'rmd': 'RMD %s\r\n',	# Remove a directory.
			# ~ 'rmda': 'RMDA\r\n',	# Remove a directory tree
			# ~ 'rnfr': 'RNFR\r\n',	# Rename from.
			# ~ 'rnto': 'RNTO\r\n',	# Rename to.
			# ~ 'site': 'SITE\r\n',	# Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands.
			'size': 'SIZE %s\r\n',	# Return the size of a file.
			# ~ 'smnt': 'SMNT\r\n',	# Mount file structure.
			# ~ 'spsv': 'SPSV\r\n',	# FTP Extension Allowing IP Forwarding (NATs) 	Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)
			'stat': 'STAT\r\n',	# Returns information on the server status, including the status of the current connection
			# ~ 'stor': 'STOR\r\n',	# Accept the data and to store the data as a file at the server site
			# ~ 'stou': 'STOU\r\n',	# Store file uniquely.
			# ~ 'stru': 'STRU\r\n',	# Set file transfer structure.
			'syst': 'SYST\r\n',	# Return system type.
# ~ 'thmb': 'THMB\r\n',	# Get a thumbnail of a remote image file
# ~ 'type': 'TYPE %s\r\n',	# Sets the transfer mode (ASCII/Binary).
			'user': 'USER %s\r\n',	# Authentication username.
			# ~ 'xcup': 'XCUP\r\n',	# Change to the parent of the current working directory
			# ~ 'xmkd': 'XMKD %s\r\n',	# Make a directory
			# ~ 'xpwd': 'XPWD\r\n',	# Print the current working directory
			# ~ 'xrpc': 'XRCP\r\n',	# ?
			# ~ 'xrmd': 'XRMD\r\n',	# Remove the directory
			# ~ 'xrsq': 'XRSQ\r\n',	# ?
			# ~ 'xsem': 'XSEM\r\n',	# Send, mail if cannot
			# ~ 'xsen': 'XSEN\r\n',	# Send to terminal 
			}

	def __init__(self, debug=False):
		self._debug = debug
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		

	def _debug_print(self, msg):
		# ~ print("[ {} ] {}={}".format(sys._getframe().f_code.co_name, title, msg))
		print("[ {} ] {}".format(inspect.stack()[1][3], msg))
		

	def set_timeout(self, timeout):
		if self._debug:
			self._debug_print("Set timeout to " + str(timeout))

		self._sock.settimeout(timeout)

	def connect(self, host):		
		self._sock.connect((host, 21))
		
		print("Connected to %s" % host)
		print(self._simple_recv())

	def disconnect(self):
		print(self._send_recv(self._cmds["quit"]))
		self._sock.close()

	def _send(self, msg):
		if self._debug:
			self._debug_print(msg)

		return self._sock.send(msg.encode())
	
	def _simple_recv(self):
		msg = self._sock.recv(2048).decode().strip()
		
		if self._debug: 
			self._debug_print(msg)
		
		return msg
		

	def _recv(self, sock):
		chunks = []

		while True:
			try:
				chunk = sock.recv(2048)
				chunks.append(chunk)
				if self._debug:
					self._debug_print("Add chunk: " + chunk.decode())
					# ~ print("[ {} ] Add chunk: {}".format(sys._getframe().f_code.co_name, chunk))
				if not chunk:
					if self._debug:
						self._debug_print("Chunk is empty.")
						# ~ print("[ {} ] Chunk is empty.".format(sys._getframe().f_code.co_name))
					break

			except socket.timeout:
				if self._debug:
					self._debug_print("Exit: Timed out.")
					# ~ print("[ {} ] Exit: Timed out.".format(sys._getframe().f_code.co_name))
				break

		return b''.join(chunks).decode().strip()



	def _send_recv(self, msg):
		if self._debug:
			self._debug_print(msg)
			
		n = self._send(msg)
		if n > 0:
			res = self._recv(self._sock)
			if self._debug:
				self._debug_print(res)			
				# ~ print("[ _send_recv ] res={}".format(res))
			# ~ else:
				# ~ print(res)
			return res

	def _pasv_transmission(self, msg):
		# Enter to PASV mode
		# ~ r = self._send_recv(self._cmds["pasv"])
		self._send('PASV\r\n')
		r = self._simple_recv()
		if self._debug:
			self._debug_print(r)
		# ~ print(r)
		answ = r.split()
		try:
			if answ[0] == "227":
				# Build a remote host and port from answer
				r_conn_data = answ[-1].strip('().').split(',')
				remote_host = ".".join(r_conn_data[:4])
				remote_port = reduce(lambda a, b: int(a)*256+int(b), r_conn_data[4:])
				if self._debug:
					self._debug_print(f"conn= {r_conn_data}")
					self._debug_print(f"{remote_host=}")
					self._debug_print(f"{remote_port=}")
				
				# Connect to remote host and receive a message
				tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
				tmp_sock.connect((remote_host, remote_port))
				
				self._send(msg)
				
				# Receive information message
				print(self._simple_recv())
				
				chunks = []
				while True:
					data = tmp_sock.recv(1024)
					if not data: break
					chunks.append(data)
					
				print(b''.join(chunks).decode().strip())
				
				tmp_sock.close()

				# Receive information message
				print(self._simple_recv())
				
		except IndexError:
			pass

	
	def _listening_socket(self, host, port, debug):		
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM ) as s:				
			s.bind((host, port))
			s.listen(1)
			if debug:
				print("Listen on {}:{}".format(host, port))
			conn, addr = s.accept()
			with conn:
				if debug:
					print("Connected by", addr)
				chunks = []
				while True:
					data = conn.recv(1024)
					if not data: break
					chunks.append(data)					
				
				print(b''.join(chunks).decode().strip())
					
			if debug: 
				print("Exit listening")

	def _port_transmission(self, msg):
		# port 9500 (37*256+28)
		p = 9500
		p1 = round(p / 256)
		p2 = p - p1 * 256
		local_addr = '10,10,10,3,{},{}'.format(p1, p2)

		# Enter PORT mode
		self._send('PORT %s\r\n' % local_addr)
		answ = self._simple_recv().split()
		print(answ)		
		if len(answ) > 0:
			if answ[0] == "200":
			
				self._send(msg)
				resp = self._simple_recv()
				print(resp)
				if resp.split()[0] == "425":
					pass
				else:
					thread = Thread(target=self._listening_socket, args=('', p, self._debug))
					thread.start()
					
					print(self._simple_recv())
				
					thread.join()
		else:
			print("Unknown error")
			
	
		
	def acct(self):
		print(self._send_recv(self._cmds["acct"]))
	
	def adat(self):
		print(self._send_recv(self._cmds["adat"]))
	
	def avbl(self):
		print(self._send_recv(self._cmds["avbl"]))
		
	def cdup(self):
		print(self._send_recv(self._cmds["cdup"]))
	
	def cwd(self, directory):
		print(self._send_recv(self._cmds["cwd"] % directory))
	
	def dele(self, f_name):
		print(self._send_recv(self._cmds["dele"] % f_name))
	
	def feat(self):
		print(self._send_recv(self._cmds["feat"]))

	def help(self):
		# ~ print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
		print(self._send_recv(self._cmds["help"]))
	
	def host(self):
		print(self._send_recv(self._cmds["host"]))
	
	def mkd(self, dir_name):
		print(self._send_recv(self._cmds["mkd"] % dir_name))

	def nlst(self, path=""):
		self._pasv_transmission(self._cmds["nlst"] % path)
		
	def noop(self):
		print(self._send_recv(self._cmds["noop"]))		
	
	def simple_cmd(self, name, arg=''):
		cmd = self._cmds_2[name]
		if arg:
			cmd = cmd % arg
		self._send(cmd)
		print(self._simple_recv())
		
		
	def pwd(self):
		print(self._send_recv(self._cmds["pwd"]))
	
	def retr(self, f_name):
		res = self._pasv_transmission(self._cmds["retr"] % f_name, verbose=False)
		if res:
			print(len(res),"bytes received")
			with open(f_name, 'w') as f:
				f.write(res)
		
	def rmd(self, dir_name):
		self._send_recv(self._cmds["rmd"] % dir_name)
		
	def size(self, fname):
		self._send_recv(self._cmds["size"] % fname)

	

	def user(self, user):
		""" Login as user """
		self._send('USER ' + user + '\r\n')
		print(self._simple_recv())
		
		pswd = getpass.getpass('Password:')
		
		self._send('PASS ' + pswd + '\r\n')
		res = self._simple_recv()
		print(res)

		if not res.split()[0] == "230":
			print("Login failed.")
			return
	
	def passive(self):
		""" Toggle passive or port mode """
		self._passive_mode = not self._passive_mode
		
		print("Passive mode:", "On" if self._passive_mode else "Off")
		
	def syst(self):
		self._send('SYST\r\n')
		print(self._simple_recv())

	def stat(self):
		self._send('STAT\r\n')
		
		# Receive reply
		chunks = []
		while True:
			chunk = self._simple_recv()
			chunks.append(chunk)
			if not chunk or "211 End" in chunk:
				break
			
		print(''.join(chunks))

	def ls(self, path="*"):
		if self._passive_mode:
			self._port_transmission('LIST %s\r\n' % path)
		else:
			self._pasv_transmission('LIST %s\r\n' % path)
		
	def _tokenizer(self, string):
		tokens = string.split()
		cmd = tokens[0]
		try:
			arg = tokens[1]
		except IndexError:
			arg = ""
		return cmd, arg

	def run(self):
		
		user = input("Name: ")
		
		self.user(user)
		
		while True:
			try:
				inpt = input(self._prompt)
				if not inpt:
					continue

				cmd, arg = self._tokenizer(inpt)
				
				if cmd == "user":
					self.user(arg)
				elif cmd == "syst":
					self.syst()
				elif cmd == "stat":
					self.stat()
				elif cmd == "ls":
					self.ls(arg)
				elif cmd == "passive":
					self.passive()
				# ~ if cmd in self._cmds_2:
					# ~ c = self._cmds_2.get(cmd)
					# ~ if c.get('send'):
						# ~ if c.get('type'):
							
					# ~ else:
						# ~ method = getattr(self, cmd)
						# ~ method()
					
					# ~ self.simple_cmd(cmd, arg)						
				elif cmd == "exit":
					break
				else:
					print("Unknown command")				
				
			except (KeyboardInterrupt, EOFError) as e:
				print("exit")
				break





if __name__ == "__main__":
	
	if len(sys.argv) < 2:
		print("Usage %s <host>" % sys.argv[0])
		sys.exit()
	
	host = sys.argv[1]
	
	ftpclient = FTPClient(debug=True)
	ftpclient.connect(host)
	
	ftpclient.run()
	
	ftpclient.disconnect()
