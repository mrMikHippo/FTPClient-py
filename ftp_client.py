import os,sys
import socket
import functools
import time
import getpass

class FTPClient:
	_prompt = "(ftp)> "
	_host = None
	_timeout = 1

	_cmds = {
			'acct': 'ACCT\r\n', # Account information.
			'adat': 'ADAT\r\n',	# Authentication/Security Data
			# ~ 'auth': 'AUTH\r\n', # Authentication/Security Mechanism
			'avbl': 'AVBL\r\n', # Get the available space
			# ~ 'ccc': 'CCC\r\n', 	# Clear Command Channel
			'cdup': 'CDUP\r\n', # Change to Parent Directory.
			# ~ 'csid': 'CSID\r\n', # Client / Server Identification
			# ~ 'cwd': 'CWD\r\n',	# Change working directory.
# ~ 'dele': 'DELE\r\n',	# Delete file.
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
# ~ 'mkd': 'MKD\r\n',	# Make directory.
			# ~ 'mlsd': 'MLSD\r\n',	# Lists the contents of a directory if a directory is named.
			# ~ 'mlst': 'MLST\r\n',	# Provides data about exactly the object named on its command line, and no others.
# ~ 'mode': 'MODE\r\n',	# Sets the transfer mode (Stream, Block, or Compressed).
			'nlst': 'NLST %s\r\n',	# Returns a list of file names in a specified directory.
			'noop': 'NOOP\r\n',	# No operation (dummy packet; used mostly on keepalives).
			# ~ 'opts': 'OPTS\r\n',	# Select options for a feature (for example OPTS UTF8 ON).
			'pass': 'PASS %s\r\n',	# Authentication password.
			'pasv': 'PASV\r\n',	# Enter passive mode.
			# ~ 'pbsz': 'PBSZ\r\n',	# Protection Buffer Size
# ~ 'port': 'PORT %s\r\n',	# Specifies an address and port to which the server should connect.
			# ~ 'prot': 'PROT\r\n',	# Data Channel Protection Level.
			'pwd': 'PWD\r\n',	# Print working directory. Returns the current directory of the host.
			'quit': 'QUIT\r\n',	# Disconnect.
			# ~ 'rein': 'REIN\r\n',	# Re initializes the connection.
			# ~ 'rest': 'REST\r\n',	# Restart transfer from the specified point.
# ~ 'retr': 'RETR\r\n',	# Retrieve a copy of the file
# ~ 'rmd': 'RMD %s\r\n',	# Remove a directory.
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

	def acct(self):
		self._send_recv(self._cmds["acct"])
	
	def adat(self):
		self._send_recv(self._cmds["adat"])
	
	def avbl(self):
		self._send_recv(self._cmds["avbl"])
		
	def cdup(self):
		self._send_recv(self._cmds["cdup"])
	
	def feat(self):
		self._send_recv(self._cmds["feat"])

	def help(self):
		# ~ print("List of Commands: https://en.wikipedia.org/wiki/List_of_FTP_commands")
		self._send_recv(self._cmds["help"])
	
	def host(self):
		self._send_recv(self._cmds["host"])
	
	def list(self, path=""):
		msg = self._cmds["list"] % path
		self._pasv_transmission(msg)

	def nlst(self, path=""):
		self._pasv_transmission(self._cmds["nlst"] % path)
		
	def noop(self):
		self._send_recv(self._cmds["noop"])
		
	def pwd(self):
		self._send_recv(self._cmds["pwd"])
		
	def size(self, fname):
		self._send_recv(self._cmds["size"] % fname)

	def syst(self):
		self._send_recv(self._cmds["syst"])

	def stat(self):
		res = self._send_recv(self._cmds["stat"], verbose=True)
		# ~ if res:
			# ~ while True:
				# ~ if res == "211 End of status":
					# ~ break

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

				is_cmd = False
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
						is_cmd = True
						break

				if not is_cmd:
					print("Unknown command")
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
