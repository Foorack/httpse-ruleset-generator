#!/usr/bin/python3

import argparse
import dns
import dns.resolver
import re
import requests
import sys
from Sublist3r import sublist3r

verbose = True

def parser_error(errmsg):
    """Argparse error handler."""
    print('Usage: python3 ' + sys.argv[0] + ' [Options] use -h for help')
    print('Error: ' + errmsg)
    exit()

def parse_args():
    """Parse program arguments."""
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

def check_domain(domain):
    """Check if the entered domain is valid."""
    domain_check = re.compile('^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$')
    return domain_check.match(domain)

def find_domains(domain, verbose):
    """Use Sublist3r to scan and find as many subdomains as possible."""
    hosts = [domain]
    hosts.extend(sublist3r.main(domain, 30, False, None, not verbose, verbose, False, 'Baidu,Yahoo,Google,Bing,Ask,Netcraft,Virustotal,SSL'))
    return hosts

def check_dns(domain):
    """Check if the entered domain has a DNS record."""
    resolver = dns.resolver.Resolver()
    # Use OpenDNS as backup because of their cache (in case of DNS downtime)
    resolver.nameservers = ['8.8.4.4', '208.67.220.220']
    try:
        ip = resolver.query(domain, 'A')[0].to_text()
        if verbose:
            print('DNS lookup for %s: %s' % (domain, ip))
        return True
    except dns.resolver.NXDOMAIN:
        return False


if __name__=='__main__':
    args = parse_args()
    
    print(check_dns("google.com"))
    print(check_dns("asdfasd"))