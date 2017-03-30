#!/usr/bin/python3

import argparse
import dns
import dns.resolver
import functools
import re
import requests
import socket
import ssl
import string
import sys
import lxml.etree
import lxml.html
from Sublist3r import sublist3r

VERSION = '4.0.0'

#
# ARGUMENT PARSING
#


def parser_error(errmsg):
    """Argparse error message handler.

    @param: errmsg Error message by argparse.

    """
    print('Usage: python3 ' + sys.argv[0] + ' [Options] use -h for help')
    print('Error: ' + errmsg)
    exit()


def parse_args():
    """Parse program arguments with argparse.

    @return: Arguments object by argparse.

    """
    parser = argparse.ArgumentParser(
        epilog='    Example: \r\npython3 ' + sys.argv[0] + ' -d eff.org')
    parser.error = parser_error
    parser._optionals.title = 'OPTIONS'
    parser.add_argument('-d', '--domain', \
        help='Domain to generate ruleset about, TLD, do not include www', required=True)
    parser.add_argument('-n', '--name', \
        help='Label the ruleset with a custom name, for example \"Electronic Frontier Foundation\"',type=str, default='')
    parser.add_argument('-t', '--timeout', \
        help='Define timeout value, this might be neccesary on slower internet connections', type=int, default=8)
    parser.add_argument('-v', '--verbose', \
        help='Enable verbosity and print debug data in realtime', action='store_true', default=False)
    return parser.parse_args()


def ruleset_generator(args):

    if not check_dns(args, args.domain):
        print("No DNS address found for domain '%s'! Exiting..." %
              (args.domain))
        return

    


if __name__ == '__main__':
    #domain, name, timeout, verbose
    ruleset_generator(parse_args())
