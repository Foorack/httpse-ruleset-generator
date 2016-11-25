#!/usr/bin/python3

import argparse
import requests
import socket
import ssl
import sys


# Agparse functions
def parser_error(errmsg):
    print('Usage: python3 ' + sys.argv[0] + ' [Options] use -h for help')
    print('Error: ' + errmsg)
    exit()

def parse_args():
    # Parse the arguments
    parser = argparse.ArgumentParser(epilog = '    Example: \r\npython3 ' + sys.argv[0] + ' -d eff.org')
    parser.error = parser_error
    parser._optionals.title = 'OPTIONS'
    parser.add_argument('-d', '--domain', help='Domain to generate ruleset about, TLD, do not include www', required=True)
    parser.add_argument('-n', '--name', help='Label the ruleset with a custom name, for example \"Electronic Frontier Foundation\"',type=str, default='')
    parser.add_argument('-t', '--timeout', help='Define timeout value, this might be neccesary on slower internet connections', type=int, default=8)
    parser.add_argument('-v', '--verbose', help='Enable verbosity and print debug data in realtime',nargs='?', default=False)
    parser.add_argument('-s', '--summary', help='Write a summary report containing more specific data regarding the scan',nargs='?', default=False)
    return parser.parse_args()






if __name__=='__main__':
    args = parse_args()