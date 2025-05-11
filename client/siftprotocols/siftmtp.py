#python3

import socket
import sys, getopt, getpass
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x01\x00'
		self.msg_hdr_rcv_sqn = b'\x00\x00'
		self.msg_hdr_snd_sqn = b'\x00\x00'
		self.msg_hdr_rsv =  b'\x00\x00'
		self.size_msg_hdr = 16 # changed to 16 for new header size
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_msg_enc_payload = 0
		self.size_msg_mac = 12
		self.size_msg_etk = 256
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		self.key = None
		self.keypath = None
		# --------- STATE ------------
		self.peer_socket = peer_socket

	# ------- UTILS --------
	def load_keypair(keyfile):
		#passphrase = input('Enter a passphrase to decode the saved key: ')
		passphrase = getpass.getpass('Enter a passphrase to decode the saved key: ')
		with open(keyfile, 'rb') as f:
			keystr = f.read()
		try:
			return RSA.import_key(keystr, passphrase=passphrase)
		except ValueError:
			print('Error: Cannot import key from file ' + keyfile)
			sys.exit(1)



	def set_final_key(self, key):
		self.key = key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'] = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'] = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'] = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# receives n bytes from the peer socket
	def receive_bytes(self, n):

		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		
		# do we have to check rsv? how do we check sqn and rnd (if even)
		if parsed_msg_hdr['rsv'] != self.msg_hdr_rsv:
			raise SiFT_MTP_Error('Incorrect reserved field value found in message header')
		
		# handle login request (first message being received)
		if self.msg_hdr_rcv_sqn == b'\x00\x00':

			if parsed_msg_hdr['typ'] != self.type_login_req:
				raise SiFT_MTP_Error('Login request expected')
			
			if parsed_msg_hdr['sqn'] != b'\x00\x01':
				raise SiFT_MTP_Error('Incorrect sequence number found in message header (should be 01)')
			
			self.size_msg_enc_payload = parsed_msg_hdr['len'] - (self.size_msg_hdr + self.size_msg_mac + self.size_msg_etk)
		
		# handle all other msgs
		else:

			if parsed_msg_hdr['sqn'] <= self.msg_hdr_rcv_sqn:
				raise SiFT_MTP_Error('Incorrect sequence number found in message header (too small)')
			
			self.size_msg_enc_payload = parsed_msg_hdr['len'] - (self.size_msg_hdr + self.size_msg_mac)
		
		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)


		enc_payload = msg_body[:self.size_msg_enc_payload]

		keypair = self.load_keypair()
		RSAcipher = PKCS1_OAEP(keypair)

		if parsed_msg_hdr['typ'] == self.type_login_req:

			etk_value = msg_body[-self.size_msg_etk:]
			mac = msg_body[-(self.size_msg_mac + self.size_msg_etk) : -self.size_msg_etk]
			try:
				self.set_final_key(RSAcipher.decrypt(etk_value))
			except ValueError:
				sys.exit(1)
		else:
			mac = msg_body[-self.size_msg_mac:]

		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
		cipher.update(msg_hdr)
		try:
			dec_payload = cipher.decrypt_and_verify(enc_payload, mac)
		except ValueError:
			sys.exit(1)

		self.msg_hdr_rcv_sqn = parsed_msg_hdr['sqn']

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		return parsed_msg_hdr['typ'], msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# if login response/request (check type):
		# msg_hdr_sqn = 0001
		# else:
		# msg_hdr_sqn = self.msg_hdr_snd_sqn + 1

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len
		# generate 6 byte rnd
		# append rnd, sqn, rsv to the header


		# generate tk for login request
		# if login request then we use tk to encrypt the payload/everything
		# otherwise we use the final key to encrypt everything

		# append etk to the message if login request


		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_payload)
			# sending message was successful, so we can set self.msg_hdr_snd_sqn = msg_hdr_sqn
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
