import os,sys
import socket
import logging
import click
from functools import reduce
import time
import getpass
from threading import Thread
import inspect
import random
from math import floor
from queue import Queue
from netaddr import IPNetwork

class FTPClient:
	_prompt = "(ftp)> "
	_passive_mode = False
	_logger = logging.getLogger(__name__)
	
	""" Commands that sends and recieves one line """
	_simple_cmds = {
		'acct': 'ACCT', # Account information.
		'adat': 'ADAT',	# Authentication/Security Data
		'avbl': 'AVBL', # Get the available space
		'cdup': 'CDUP', # Change to Parent Directory.
		'cd': 'CWD',	# Change working directory.
		'rm': 'DELE',	# Delete file.
		'mkdir': 'MKD',	# Make directory.
		'rmdir': 'RMD',	# Remove a directory.
		'pwd': 'PWD',	# Print working directory. Returns the current directory of the host.
		'noop': 'NOOP',	# No operation (dummy packet; used mostly on keepalives).
		'size': 'SIZE',	# Return the size of a file.
		'dsiz': 'DSIZ',	# Get the directory size
		'syst': 'SYST',	# Return system type.
	}
	
	_cmds = {
			# ~ 'auth': 'AUTH\r\n', # Authentication/Security Mechanism
			# ~ 'ccc': 'CCC\r\n', 	# Clear Command Channel
			# ~ 'csid': 'CSID\r\n', # Client / Server Identification
# ~ 'dsiz': 'DSIZ\r\n',	# Get the directory size
			# ~ 'eprt': 'EPRT\r\n',	# Specifies an extended address and port to which the server should connect.
			# ~ 'epsv': 'EPSV\r\n',	# Enter extended passive mode.
# ~ 'feat': 'FEAT\r\n',	# Get the feature list implemented by the server.
# ~ 'help': 'HELP\r\n',	# Returns usage documentation on a command if specified, else a general help document is returned.
# ~ 'host': 'HOST\r\n',	# Identify desired virtual host on server, by name.
			# ~ 'lang': 'LANG\r\n',	# Language Negotiation
			# ~ 'lprt': 'LPRT\r\n',	# Specifies a long address and port to which the server should connect.
			# ~ 'lpsv': 'LPSV\r\n',	# Enter long passive mode.
# ~ 'mdtm': 'MDTM\r\n',	# Return the last-modified time of a specified file.
			# ~ 'mcft': 'MFCT\r\n',	# Modify the creation time of a file.
			# ~ 'mff': 'MFF\r\n',	# Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
			# ~ 'mfmt': 'MFMT\r\n',	# Modify the last modification time of a file.
			# ~ 'mic': 'MIC\r\n',	# Integrity Protected Command
			# ~ 'mlsd': 'MLSD\r\n',	# Lists the contents of a directory if a directory is named.
			# ~ 'mlst': 'MLST\r\n',	# Provides data about exactly the object named on its command line, and no others.
# ~ 'mode': 'MODE\r\n',	# Sets the transfer mode (Stream, Block, or Compressed).
# ~ 'nlst': 'NLST %s\r\n',	# Returns a list of file names in a specified directory.
# ~ 'noop': 'NOOP\r\n',	# No operation (dummy packet; used mostly on keepalives).
			# ~ 'opts': 'OPTS\r\n',	# Select options for a feature (for example OPTS UTF8 ON).
			# ~ 'pbsz': 'PBSZ\r\n',	# Protection Buffer Size
			# ~ 'prot': 'PROT\r\n',	# Data Channel Protection Level.
			# ~ 'rein': 'REIN\r\n',	# Re initializes the connection.
			# ~ 'rest': 'REST\r\n',	# Restart transfer from the specified point.
			'retr': 'RETR %s\r\n',	# Retrieve a copy of the file
			# ~ 'rmda': 'RMDA\r\n',	# Remove a directory tree
			# ~ 'rnfr': 'RNFR\r\n',	# Rename from.
			# ~ 'rnto': 'RNTO\r\n',	# Rename to.
			# ~ 'site': 'SITE\r\n',	# Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands.
			# ~ 'smnt': 'SMNT\r\n',	# Mount file structure.
			# ~ 'spsv': 'SPSV\r\n',	# FTP Extension Allowing IP Forwarding (NATs) 	Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections)
			# ~ 'stor': 'STOR\r\n',	# Accept the data and to store the data as a file at the server site
			# ~ 'stou': 'STOU\r\n',	# Store file uniquely.
			# ~ 'stru': 'STRU\r\n',	# Set file transfer structure.
# ~ 'thmb': 'THMB\r\n',	# Get a thumbnail of a remote image file
# ~ 'type': 'TYPE %s\r\n',	# Sets the transfer mode (ASCII/Binary).
			# ~ 'xcup': 'XCUP\r\n',	# Change to the parent of the current working directory
			# ~ 'xmkd': 'XMKD %s\r\n',	# Make a directory
			# ~ 'xpwd': 'XPWD\r\n',	# Print the current working directory
			# ~ 'xrpc': 'XRCP\r\n',	# ?
			# ~ 'xrmd': 'XRMD\r\n',	# Remove the directory
			# ~ 'xrsq': 'XRSQ\r\n',	# ?
			# ~ 'xsem': 'XSEM\r\n',	# Send, mail if cannot
			# ~ 'xsen': 'XSEN\r\n',	# Send to terminal 
			}

	def __init__(self, verbose=False):
		self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		self.setuplog(verbose)

	# ~ def _debug_print(self, msg):
		# ~ print("[ {} ] {}={}".format(sys._getframe().f_code.co_name, title, msg))
		# ~ print("[ {} ] {}".format(inspect.stack()[1][3], msg))

	def setuplog(self, verbose):
		if verbose:
			log_msg_format = "[ %(funcName)s ] %(message)s"
		else:
			log_msg_format = "%(message)s"
			
		logging.basicConfig(format=log_msg_format)
		
		if verbose:
			self._logger.setLevel(logging.DEBUG)
		else:
			self._logger.setLevel(logging.INFO)

	def set_timeout(self, timeout):
		self._logger.debug(f"Set timeout to {timeout}")

		self._sock.settimeout(timeout)

	def connect(self, host):		
		self._sock.connect((host, 21))
		
		# ~ self._host = host
		
		f = os.popen('ifconfig |grep "inet " | awk \'{ print $2 }\'')
		local_ips = f.read()
		
		self._logger.debug(local_ips)

		for ip in local_ips.split():
			if IPNetwork(f"{ip}/24") == IPNetwork(f"{host}/24"):
				self._local_host = ip

		self._logger.debug(f"local ip: {self._local_host}")

		print("Connected to %s" % host)
		print(self._simple_recv())

	def disconnect(self):
		""" Disconnect. """
		self._send('QUIT\r\n')
		print(self._simple_recv())
		self._sock.close()

	def _send(self, msg):
		
		self._logger.debug(msg)

		return self._sock.send(msg.encode())
	
	def _simple_recv(self):
		msg = self._sock.recv(2048).decode().strip()
		
		self._logger.debug(msg)

		return msg
		

	def _recv(self, sock):
		chunks = []

		while True:
			try:
				chunk = sock.recv(2048)
				chunks.append(chunk)
				
				self._logger.debug(f"Add chunk: {chunk.decode()}")

				if not chunk:
					self._logger.debug("Chunk is empty.")					
					break

			except socket.timeout:
				self._logger.debug("Exit: Timed out.")				
				break

		return b''.join(chunks).decode().strip()
	
	def _simple_transmit(self, cmd, arg=''):
		
		s_cmd = self._simple_cmds[cmd]
		
		if arg:
			s_cmd += ' ' + arg

		s_cmd += '\r\n'
		
		self._logger.debug(s_cmd)		

		self._send(s_cmd)
		print(self._simple_recv())
	
	def _transmit_with_211_end(self, cmd):
		self._send(cmd + '\r\n')
		
		# Receive reply
		chunks = []
		while True:
			chunk = self._simple_recv()
			chunks.append(chunk)
			if not chunk or "211 End" in chunk:
				break
			
		return ''.join(chunks)
		
	def _tokenizer(self, string):
		tokens = string.split()
		cmd = tokens[0]
		try:
			arg = tokens[1]
		except IndexError:
			arg = ""
		return cmd, arg

	def _extract_host_and_port(self, msg):
		""" 
			Extract host and port from received message after PORT command 
			f.e. (10,10,10,4,27,96)
		"""
		cdata = msg.split()[-1].strip('().').split(',')
		rhost = ".".join(cdata[:4])
		rport = reduce(lambda a, b: int(a)*256+int(b), cdata[4:])
		
		self._logger.debug(f"conn= {cdata}\n{rhost=}\n{rport=}")
		
		return rhost, rport

	def _pasv_transmission(self, msg, prnt=True):
		# Enter to PASV mode
		self._send('PASV\r\n')
		r = self._simple_recv()
		
		self._logger.debug(r.split())		
		
		status_code = self._extract_status_code(r)
		if status_code == "227":
			# Build a remote host and port from answer
			rhost, rport = self._extract_host_and_port(r)
			
			# Connect to a remote host
			tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
			tmp_sock.connect((rhost, rport))
			
			# Send message
			self._send(msg)
			
			# Receive information message
			print(self._simple_recv())
			
			chunks = []
			while True:
				data = tmp_sock.recv(1024)
				if not data: break
				chunks.append(data)
			
			if prnt:
				print(b''.join(chunks).decode().strip())
			
			tmp_sock.close()

			# Receive information message
			print(self._simple_recv())
			
			return b''.join(chunks).decode().strip()
				
		else:
			print(r)

	
	def _listening_socket(self, host, port, debug):
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM ) as s:
			s.bind((host, port))
			s.listen()
			
			# ~ self._logger.debug(f"Listen on {host}:{port}"
			if debug: print("[ {} ] Listen on {}:{}".format(inspect.stack()[0][3], host, port))
			
			conn, addr = s.accept()
			if debug: print("[ {} ] Accepted".format(inspect.stack()[0][3]))
			
			with conn:
				if debug: print("[ {} ] Connected by {}".format(inspect.stack()[0][3], addr))
				
				chunks = []
				while True:					
					data = conn.recv(1024)
					if not data: break					
					chunks.append(data)					
				
			if debug: 
				print("[ {} ] Exit listening".format(inspect.stack()[0][3]))
			
			return b''.join(chunks).decode().strip()
			
	def _extract_status_code(self, msg):
		arr = msg.split()
		status_code = -1
		
		if arr:
			status_code = arr[0]		

		return status_code
			
			
	
	def _port_transmission(self, msg, prnt=True):
		
		# port 9500 (37*256+28)
		p = 9501
		p1 = floor(p / 256)
		p2 = p - p1 * 256		
		
		self._logger.debug(f"{p = }, {p1 = }, {p2 = }")
			
		
		# ~ local_addr = '10,10,10,3,{},{}'.format(p1, p2)
		local_addr = '{},{},{}'.format(self._local_host.replace('.', ','), p1, p2)

		# Specifies an address and port to which the server should connect.
		self._send('PORT %s\r\n' % local_addr)
		answ = self._simple_recv()
		print(answ)
		
		status_code = self._extract_status_code(answ)
		
		if status_code == "200":
			
			que = Queue()
				
			# Start listening socket in thread
			thread = Thread(target=lambda q, host, port, debug: q.put(self._listening_socket(host, port, debug)), 
							args=(que, '', p, logging.getLevelName(self._logger.level) == 'DEBUG'))
			thread.start()				
				
			self._send(msg)
			resp = self._simple_recv()
			print(resp)

			result = str()
			st_code = self._extract_status_code(resp)
			if st_code == "150":
				
				# Receive data				
				result = que.get()
				if prnt:
					print(result)
				# ~ que.task_done()
				# ~ que.join()
				print(self._simple_recv())
			else:
				# Connecting to given port for getting accepted listening socket in thread
				# if status code is not 150
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM ) as s:					
					s.connect(('',p))
					s.close()
				
			thread.join()
				
			return result
		# ~ else:
			# ~ print("Unknown error")
			
	
	def user(self, user):
		""" Authentication """

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
		
	def status(self):
		""" 
			Returns information on the server status, 
			including the status of the current connection
		"""
		print(self._transmit_with_211_end('STAT'))
	
	def features(self):
		""" Get the feature list implemented by the server. """
		print(self._transmit_with_211_end('FEAT'))		

	def ls(self, path="*"):
		""" 
			Returns information of a file or directory if specified, 
			else information of the current working directory is returned. 
		"""
		if self._passive_mode:
			self._pasv_transmission('LIST %s\r\n' % path)
		else:
			self._port_transmission('LIST %s\r\n' % path)
	
	def nlist(self, path="*"):
		"""
			Returns a list of file names in a specified directory.
		"""
		if self._passive_mode:
			self._pasv_transmission('NLST %s\r\n' % path)
		else:
			self._port_transmission('NLST %s\r\n' % path)
			
	def get(self, f_name):
		""" Retrieve file from server """
		
		if self._passive_mode:
			res = self._pasv_transmission('RETR %s\r\n' % f_name, prnt=False)
		else:
			res = self._port_transmission('RETR %s\r\n' % f_name, prnt=False)
			
		if res:
			print(len(res),"bytes received")
			with open(f_name, 'w') as f:
				f.write(res)
	
	

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
				elif cmd == "status":
					self.status()
				elif cmd == "feat":
					self.features()
				elif cmd == "ls":
					self.ls(arg)
				elif cmd == "nlist":
					self.nlist(arg)
				elif cmd == "passive":
					self.passive()
				elif cmd == "get":
					self.get(arg)
				elif cmd in self._simple_cmds:
					self._simple_transmit(cmd, arg)
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

@click.command()
@click.option('--host', help="ftp host address", required=True)
@click.option('--verbose', help="verbose output", default=False, is_flag=True)
def start_ftp(host, verbose):
	
	
	ftpclient = FTPClient(verbose)
	ftpclient.connect(host)
	
	ftpclient.run()
	
	ftpclient.disconnect()
	

if __name__ == "__main__":
	start_ftp()

