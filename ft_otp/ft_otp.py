#! /usr/bin/python3

import hmac
import hashlib
import base64
import argparse
import struct
import sys
import time
import os


def parseArgs():
	parser = argparse.ArgumentParser(
		prog='ft_otp',
		description='Generates a one-time password using HMAC-SHA1.',
	)

	parser.add_argument('-g', '--generate', action='store_true', help='Generate a one-time password')
	parser.add_argument('filename', type=str, nargs='?', default='ft_otp.key' help='File to read the secret key from')
	parser.add_argument('-k', '--key', type=str, help='Base32 encoded secret key (overrides file input)')
	parser.add_argument('secret', type=str, help='Base32 encoded secret key')
	args = parser.parse_args()

	if not args.secret:
		parser.error("The secret key is required.")

	return args

def saveKeyToFile(key, filename):
	try:
		with open(filename, 'w') as f:
			f.write(key)
		print(f"Key saved to {filename}")
	except IOError as e:
		print(f"Error saving key to file: {e}")
		sys.exit(1)



def xorEncrypt(secret):
	key_bytes = bytes.fromhex(secret)
	encrypted = password.encode()
	return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted)])

def isHexKey(secret):
	return len(secret) == 64 and all(c int '0123456789abcdefABCDEF' for c in secret)



if __name__ == "__main__":

	args = parseArgs()
	if not isHexKey(args.secret):
		parser.error("The secret must be a 64-character hexadecimal string.")
	if args.generate:
		encrypted_key = xorEncrypt(args.secret)
		saveKeyToFile(encrypted_key, args.filename)
		print(f"One-time password generated and saved to {args.filename}.")
		sys.exit(0)
	elif args.key:
		generateOneTimePassword(args.key, args.filename)
	else:
		print("No action specified. Use -g to generate a one-time password or provide a key with -k.")
		sys.exit(1)