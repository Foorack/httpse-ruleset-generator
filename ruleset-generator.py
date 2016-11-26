#!/usr/bin/python3

import argparse
import dns
import dns.resolver
import re
import requests
import socket
import sys
from lxml import html
from lxml import etree
from Sublist3r import sublist3r

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
    """Check if the domain successfully matches against the domain regex.

    @param: domain Domain to check against.
    @return: If the domain is valid or not.

    """
    domain_check = re.compile('^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$')
    return domain_check.match(domain)

def find_domains(args):
    """Use Sublist3r to scan and find as many subdomains as possible.

    @param: ags Arguments object from argparse.
    @return: List of domains found by Sublist3r.

    """
    domains = [args.domain]
    domains.extend(sublist3r.main(args.domain, 30, False, None, not args.verbose, args.verbose, False, 'Baidu,Yahoo,Google,Bing,Ask,Netcraft,Virustotal,SSL'))
    return domains

def check_dns(args, domain):
    """Check if the entered domain has a DNS record.
    Hardcoded DNS servers are Google DNS and OpenDNS
    (for redundancy and becuase OpenDNS cache records).

    @param: args Arguments object from argparse.
    @param: domain Domain to check against.
    @return: True if exists, False if not.

    """
    resolver = dns.resolver.Resolver()
    # Use OpenDNS as backup because of their cache (in case of DNS downtime)
    resolver.nameservers = ['8.8.4.4', '208.67.220.220']
    try:
        ip = resolver.query(domain, 'A')[0].to_text()
        if args.verbose:
            print('DNS lookup for %s: %s' % (domain, ip))
        return True
    except dns.resolver.NXDOMAIN:
        return False

def check_mcb(args, summary, domain, recursive, root):
    """Iterates and scans for Mixed Content Blocking.
    Will follow links 1 level deep. Does not yet check css files.

    @param: args Arguments object from argparse.
    @param: summary Summary object used to collect detailed scan information.
    @param: domain Domain to check against.
    @param: recursive If the scan should continue to other links.
    @param: root Content document HTML root.
    @return: True if MCB detected, False if not.

    """
    if len(root) > 0:
        for child in root:
            if check_mcb(args, summary, domain, True, child):
                return True
    else:
        if root.tag == 'script' and root.get('src') != None and root.get('src').startswith('http://'):
            return True
        if root.tag == 'iframe' and root.get('src') != None and root.get('src').startswith('http://'):
            return True
        if root.tag == 'link' and root.get('href') != None and root.get('href').startswith('http://'):
            if root.get('type') != None:
                if root.get('type') == 'text/css':
                    return True
            else:
                return True
        if root.tag == 'object' and root.get('data') != None and root.get('data').startswith('http://'):
            return True

        if domain != None and root.tag == 'a' and root.get('href') != None:
            href = root.get('href')
            path = ''
            if (href.startswith('https://') or href.startswith('http://')) and len(href.split('/')) >= 4:
                mcbhrefd = href.split('/')
                if mcbhrefd[2] == domain:
                    path = mcbhrefd[3]
                else:
                    return False
            else: # Must be a file then
                path = href

            # Recursively check 1 level deep
            try:
                if check_mcb(args, summary, domain, False, html.fromstring(make_request(args, True, domain, path).content)):
                    print(domain, path) # TODO
                    return True
            except lxml.etree.XMLSyntaxError:
                ()
    return False

def check_same_content(args, summary, respc, respsc):
    return False #FIXME

def check_chrome_301_header_trunc(args, summary, resps):
    for hre in resps.history:
        if hre.status_code == 301 or hre.status_code == 302: # do 302 as well :)
            CRLF = '\r\n'

            addr = '/'
            if(len(hre.url.split('/')) > 3):
                addr = hre.url[(7 + len(hre.url.split('/')[2])):]

            request = [
                'GET ' + addr + ' HTTP/1.1',
                'Host: ' + hre.url.split('/')[2],
                'Connection: Close',
                '',
                '',
            ]

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            wrappedSocket = ssl.wrap_socket(sock)

            wrappedSocket.connect((hre.url.split('/')[2], 443))
            wrappedSocket.send(CRLF.join(request).encode('utf-8'))
            # Get the response (in several parts, if necessary)
            response = wrappedSocket.recv(4096)

            wrappedSocket.close()

            # HTTP headers will be separated from the body by an empty line
            header_data, ll, body = response.decode('utf-8').partition(CRLF + CRLF)

            return ll != '\r\n\r\n'
    return False

def get_links(root):
    """Iterates and gathers all links on the website.

    @param: root Content document HTML root.
    @return: Array of all found links.

    """
    arr = []
    if len(root) > 0:
        for child in root:
            arr.append(child)
    else:
        if root.tag == 'script' and root.get('src') != None and root.get('src').startswith('http://'):
            arr.append(root.get('src'))
        if root.tag == 'iframe' and root.get('src') != None and root.get('src').startswith('http://'):
            arr.append(root.get('src'))
        if root.tag == 'link' and root.get('href') != None and root.get('href').startswith('http://'):
            if root.get('type') != None:
                if root.get('type') == 'text/css':
                    arr.append(root.get('href'))
            else:
                arr.append(root.get('href'))
        if root.tag == 'object' and root.get('data') != None and root.get('data').startswith('http://'):
            arr.append(root.get('data'))

        if root.tag == 'a' and root.get('href') != None:
            arr.append(root.get('href'))
    return arr

def make_request(args, https, domain, url=''):
    """Makes a request to the entererd domain and url using requests.
    Timeout value equals 'timeout' argument. Allow redirects enabled.
    Uses custom User-Agent and could therefore get non-browser behaviour.

    @param: args Arguments object from argparse.
    @param: https Toggle for use of HTTPS.
    @param: domain Domain to check against.
    @param: url Optional website URL
    @return: Request object representing the closed HTTP connection.

    """
    if https:
        protocol = 'https://'
    else:
        procotol = 'http://'
    return requests.get(protocol + domain + '/' + url, \
        timeout=args.timeout, \
        allow_redirects=True, \
        headers={ \
            'User-Agent': 'HTTPSE-ruleset-generator scan. ' +
                'Internet security project https://github.com/Foorack/httpse-ruleset-generator.',
            'Connection':'close'
        })

def process_success(args, results, summary, domain, resp, resps):
    """Processes domains further before finally marking them
    as success. Further information can be found in the flowchart.

    @param: args Arguments object from argparse.
    @param: results Results object containing scan operational data.
    @param: summary Summary object used to collect detailed scan information.
    @param: domain Domain to check against.
    @param: resp Request object representing the HTTP connection.
    @param: resps Request object representing the HTTPS connection.

    """
    if resps.status_code == 403:
        if resp.status_code == 200:
            results['error']['403'].append(domain)
        else:
            if resp.url.startswith('https://'):
                links = get_links(resp.content)
                for link in links:
                    if link.startswith('http://'):
                        continue

                    if link.startswith('https://' + domain) or link.startswith('//' + domain):
                        r2 = make_request(args, True, domain, link.split('/')[4])
                    elif link.startswith('/'):
                        r2 = make_request(args, True, domain, link[1:])
                    else:
                        r2 = make_request(args, True, domain, link)

                    if r2.status_code == 200:
                        results['success'].append([domain, r2.url])
                        return

            links = get_links(resps.content)
            for link in links:
                if link.startswith('http://'):
                    continue

                if link.startswith('https://' + domain) or link.startswith('//' + domain):
                    r2 = make_request(args, True, domain, link.split('/')[4])
                elif link.startswith('/'):
                    r2 = make_request(args, True, domain, link[1:])
                else:
                    r2 = make_request(args, True, domain, link)

                if r2.status_code == 200:
                    results['success'].append([domain, r2.url])
                    return
            results['error']['no_working_url_known'].append(domain)
        return

    if resps.status_code == 503:
        if resp.status_code == 200:
            results['error']['503'].append(domain)
        else:
            results['error']['no_working_url_known'].append(domain)
        return

    if resps.status_code == 504:
        if resp.status_code == 200:
            results['error']['504'].append(domain)
        else:
            results['error']['no_working_url_known'].append(domain)
        return

    if check_mcb(args, summary, domain, True, html.fromstring(resps.content)):
        results['error']['mixed_content'].append(domain)
        return

    if not check_same_content(args, summary, resp.content, resps.content):
        results['error']['different_content'].append(domain)
        return

    if check_chrome_301_header_trunc(args, summary, resps):
        results['rules'].append([domain, resps.url])
        return

    results['success'].append([domain])

def test_domain(args, results, summary, domain):
    """Tests a domain if it has functional HTTPS support, and if
    not then it checks most scenarios and classifies it appropriately.

    @param: args Arguments object from argparse.
    @param: results Results object containing scan operational data.
    @param: summary Summary class used to collect detailed scan information.
    @param: domain Domain to check against.

    """
    if not check_dns(args, args.domain):
        if args.verbose:
            print("No DNS address found for sub-domain '%s'! Skipping..." % (args.domain))
        return

    resp, resps = None, None

    def do_http():
        try:
            resp = make_request(args, False, domain)
        except requests.exceptions.ConnectionError:
            ()
        except requests.exceptions.Timeout or socket.timeout:
            ()

    # Only do HTTP if neccesary
    try:
        resps = make_request(args, True, args.domain)
        do_http()
    except requests.exceptions.SSLError as err:
        msg = str(err)
        if 'doesn\'t match' in msg:
            do_http()
            if resp == None:
                results['error']['invalid_certificate'].append(domain)
                return

            # Check if HTTP redirects to a working HTTPS website
            if resp.url.startswith('https://'):
                if not resp.url.startswith('https://' + domain):
                    results['rules'].append([domain, resp.url])
            else:
                if len(resp.history) > 0:
                    results['tmp']['invalid_certificate'].append([domain, resp.url[7:]])
                else:
                    results['error']['invalid_certificate'].append(domain)
            return
        elif 'CERTIFICATE_VERIFY_FAILED' in msg:
            results['error']['incomplete_certificate_chain'].append(domain)
            return
        else:
            results['error']['unknown_ssl_error'].append(domain)
            return
    except requests.exceptions.Timeout or socket.timeout as err:
        results['error']['timeout'].append(domain)
        return
    except requests.exceptions.RequestException as err:
        results['error']['refused'].append(domain)
        return

    if resp == None:
        results['success'].append([domain])

    if resp.url.startswith('https://' + domain):
        results['success'].append([domain])

    if resps.url.startswith('http://'):
        if resp.url.startswith('http://' + domain) or resp.url.startswith('https://' + domain):
            results['success'].append([domain])
        else:
            results['tmp']['redirect_to_http'].append(domain)
        return

    if not resp.url.startswith('http://' + domain) and not resp.url.startswith('https://' + domain):
        results['success'].append([domain])
        return

    if resp.url.startswith('https://'):
        results['rules'].append([domain, resp.url])
    else:
        results['tmp']['redirect_to_http'].append(domain)

def ruleset_generator(args):

    if not check_dns(args, args.domain):
        print("No DNS address found for domain '%s'! Exiting..." % (args.domain))
        return

    results = {
        'tmp': {
            'invalid_certificate': [],
            'redirect_to_http': [],
        },
        'error': {
            'timeout': [],
            'refused': [],
            'incomplete_certificate_chain': [],
            'invalid_certificate': [],
            'unknown_ssl_error': [],
            'no_working_url_known': [],
            'mixed_content': [],
            'different_content': [],
            'redirect_to_http': [],
            '403': [],
            '503': [],
            '504': [],
        },
        'success': [],
        'rules': []
    }

    summary = {}

    domains = find_domains(args)

    [test_domain(args, results, summary, domain) for domain in domains]

    # TODO print results
    # TODO summary report

if __name__=='__main__':
    #domain, name, timeout, verbose, summary
    ruleset_generator(parse_args())