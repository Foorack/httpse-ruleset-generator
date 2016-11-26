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

VERSION = '3.0.0'

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
    parser.add_argument('-d', '--domain', \
        help='Domain to generate ruleset about, TLD, do not include www', required=True)
    parser.add_argument('-n', '--name', \
        help='Label the ruleset with a custom name, for example \"Electronic Frontier Foundation\"',type=str, default='')
    parser.add_argument('-t', '--timeout', \
        help='Define timeout value, this might be neccesary on slower internet connections', type=int, default=8)
    parser.add_argument('-v', '--verbose', \
        help='Enable verbosity and print debug data in realtime', action='store_true', default=False)
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
    domains.extend(sublist3r.main(args.domain, 30, False, None, \
    not args.verbose, args.verbose, False, \
    'Baidu,Yahoo,Google,Bing,Ask,Netcraft,Virustotal,SSL'))
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
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
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
            if check_mcb(args, summary, domain, recursive, child):
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
            elif root.get('rel') != None:
                if root.get('rel') == "stylesheet":
                    return True
            elif root.get('as') != None:
                if root.get('as') == "style":
                    return True
            else:
                return True
        if root.tag == 'object' and root.get('data') != None and root.get('data').startswith('http://'):
            return True

        if recursive and domain != None and root.tag == 'a' and root.get('href') != None:
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
            if check_mcb(args, summary, domain, False, \
                lxml.html.fromstring(sanitize_input(make_request(args, True, domain, path).text))):
                print(domain, path) # TODO
                return True
    return False

def sanitize_input(text):
    printable = set(string.printable)
    finish = []
    [(finish.append(x) if x in printable else 0) for x in text]
    return "".join(finish)

def check_same_content(args, summary, respc, respsc):

    hresp, hresps = None, None
    hresp1 = lxml.html.fromstring(sanitize_input(respc.text))
    hresp2 = lxml.html.fromstring(sanitize_input(respsc.text))

    # XOR: Check if one is malformed and one is not.
    if (hresp1 == None) != (hresp2 != None):
        return False

    # XOR: Check if one has a html body and one does not.
    if (hresp1.tag == 'html') != (hresp2.tag == 'html'):
        return False

    head1 = hresp1.find('head')
    head2 = hresp2.find('head')

    # XOR: Check if one has a head and one does not.
    if (head1 is None) != (head2 is None):
        return False

    title1 = head1.find('title')
    title2 = head2.find('title')

    # Check webpage titles
    if (title1 is None) != (title2 is None):
        return False
    if title1 is not None and title2 is not None and title1 != title2:
        return False

    links1, links2 = [], []
    [(links1.append(link) if link.split('?')[0].endswith('.css') else ()) for link in get_links(respc)]
    [(links2.append(link) if link.split('?')[0].endswith('.css') else ()) for link in get_links(respsc)]
    
    # HTTP and HTTPS versions might have different JS but should have the same CSS
    if len(links1) != len(links2):
        return False

    return True

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
            elif root.get('rel') != None:
                if root.get('rel') == "stylesheet":
                    arr.append(root.get('href'))
            elif root.get('as') != None:
                if root.get('as') == "style":
                    arr.append(root.get('href'))
            else:
                arr.append(root.get('href'))
        if root.tag == 'object' and root.get('data') != None and root.get('data').startswith('http://'):
            arr.append(root.get('data'))
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
    protocol = ''
    if https:
        protocol = 'https://'
    else:
        protocol = 'http://'

    return requests.get(protocol + domain + '/' + url, \
        timeout=args.timeout, \
        allow_redirects=True, \
        headers={ \
            'User-Agent': 'HTTPSE-ruleset-generator scan. ' +
                'Internet security project https://github.com/Foorack/httpse-ruleset-generator.',
            'Connection':'close'
        })

# https://github.com/jeremyn/Sublist3r/blob/09a2b9cdaf020a7dac6701765a846807ef6db814/sublist3r.py#L82
def subdomain_cmp(d1, d2):
    '''cmp function for subdomains d1 and d2.
    This cmp function orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:
    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]
    '''
    d1 = d1[0].split('.')[::-1]
    d2 = d2[0].split('.')[::-1]

    val = 1 if d1>d2 else (-1 if d1<d2 else 0)
    if ((len(d1) < len(d2)) and
        (d1[-1] == 'www') and
        (d1[:-1] == d2[:len(d1)-1])):
        val = -1
    elif ((len(d1) > len(d2)) and
          (d2[-1] == 'www') and
          (d1[:len(d2)-1] == d2[:-1])):
        val = 1
    elif d1[:-1] == d2[:-1]:
        if d1[-1] == 'www':
            val = -1
        elif d2[-1] == 'www':
            val = 1
    return val

def process_success(args, results, summary, domain, resp, resps, tests=None):
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
                links = get_links(resp.text)
                for link in links:
                    if link.startswith('http://'):
                        continue

                    if link.startswith('https://' + domain) or link.startswith('//' + domain):
                        r2 = make_request(args, True, domain, link.split('/')[3])
                    elif link.startswith('/'):
                        r2 = make_request(args, True, domain, link[1:])
                    else:
                        r2 = make_request(args, True, domain, link)

                    if r2.status_code == 200:
                        process_success(args, results, summary, domain, resp, resps, [r2.url])
                        return

            links = get_links(resps.text)
            for link in links:
                if link.startswith('http://'):
                    continue

                if link.startswith('https://' + domain) or link.startswith('//' + domain):
                    r2 = make_request(args, True, domain, link.split('/')[3])
                elif link.startswith('/'):
                    r2 = make_request(args, True, domain, link[1:])
                else:
                    r2 = make_request(args, True, domain, link)

                if r2.status_code == 200:
                    process_success(args, results, summary, domain, resp, resps, [r2.url])
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

    if check_mcb(args, summary, domain, True, lxml.html.fromstring(sanitize_input(resps.text))):
        results['error']['mixed_content'].append(domain)
        return

    if resp != None and not check_same_content(args, summary, resp.text, resps.text):
        if resp.url.startswith('https://' + domain) and len(resp.url.split('/')[3]) > 2 and resp.url != resps.url:
            results['rules'][''].append([domain, resp.url, False])
        else:
            results['error']['different_content'].append(domain)
        return

    if check_chrome_301_header_trunc(args, summary, resps):
        results['rules'].append([domain, resps.url, True])
        return
    
    res = [domain]
    if tests != None:
        res.extend(tests)
    results['success'].append(res)

def test_domain(args, results, summary, domain):
    """Tests a domain if it has functional HTTPS support, and if
    not then it checks most scenarios and classifies it appropriately.

    @param: args Arguments object from argparse.
    @param: results Results object containing scan operational data.
    @param: summary Summary class used to collect detailed scan information.
    @param: domain Domain to check against.

    """
    if not check_dns(args, domain):
        if args.verbose:
            print("No DNS address found for sub-domain '%s'! Skipping..." % (domain))
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
                    results['rules'].append([domain, resp.url, False])
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
            results['error']['other_ssl_error'].append(domain)
            return
    except requests.exceptions.Timeout or socket.timeout as err:
        results['error']['timeout'].append(domain)
        return
    except requests.exceptions.RequestException as err:
        results['error']['refused'].append(domain)
        return

    if resp == None:
        process_success(args, results, summary, domain, resp, resps)
        return

    if resp.url.startswith('https://' + domain):
        process_success(args, results, summary, domain, resp, resps)
        return

    if resps.url.startswith('http://'):
        if resp.url.startswith('http://' + domain) or resp.url.startswith('https://' + domain):
            process_success(args, results, summary, domain, resp, resps)
        else:
            results['tmp']['redirect_to_http'].append(domain)
        return

    if not resp.url.startswith('http://' + domain) and not resp.url.startswith('https://' + domain):
        process_success(args, results, summary, domain, resp, resps)
        return

    if resp.url.startswith('https://'):
        results['rules'].append([domain, resp.url, False])
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
            '403': [],
            '503': [],
            '504': [],
            'different_content': [],
            'incomplete_certificate_chain': [],
            'invalid_certificate': [],
            'mixed_content': [],
            'no_working_url_known': [],
            'other_ssl_error': [],
            'redirect_to_http': [],
            'refused': [],
            'timeout': [],
        },
        'success': [],
        'rules': []
    }

    summary = {}
    domains = find_domains(args)
    [test_domain(args, results, summary, domain) for domain in domains]

    # Process TMP
    # Check if HTTPS redirects to a HTTP site which we already redirect to HTTPS
    for hr in results['tmp']['redirect_to_http']:
        def dd1():
            for host in results['success']:
                if hr[1].startswith(host):
                    if hr[2]:
                        results['rules'].append([hr[0], hr[1], True]) # 301 bug /w chrome
                    else:
                        results['success'].append(hr[0])
                    return True
            return False
        if not dd1():
            results['error']['redirect_to_http'].append(hr[0])
    
    # Check if hosts with bad cert HTTP-redirect to a good host
    for hr in results['tmp']['invalid_certificate']:
        def dd2():
            for host in results['success']:
                if hr[1].startswith(host):
                    results['rules'].append([hr[0], 'https://' + hr[1], False])
                    return True
            return False
        if not dd2():
            results['error']['invalid_certificate'].append(hr[0])
    
    # Final fixes
    for rule in results['rules']:
        results['success'].append(rule[0])
    
    # Do not make a ruleset if we have 0 successful domains
    if len(results['success']) == 0:
        print("No successful domains found. :(")
        #return
    
    # Sort domains the way we want it
    results['success'] = sorted(
            results['success'],
            key=functools.cmp_to_key(subdomain_cmp),
    )
    results['error']['invalid_certificate'] = sorted(
            results['error']['invalid_certificate'],
            key=functools.cmp_to_key(subdomain_cmp),
    )
    results['error']['redirect_to_http'] = sorted(
            results['error']['redirect_to_http'],
            key=functools.cmp_to_key(subdomain_cmp),
    )

    # TODO print results
    
    has_bad_domains = False
    for a in results['error']:
        if len(results['error'][a]) > 0:
            has_bad_domains = True
    
    f = open(args.domain + '.xml', 'w')
    f.write('<!--\n')
    f.write('\n')
    f.write('\tGenerator: HTTPSE-ruleset-generator v%s\n' % (VERSION))
    f.write('\tSummary report: https://gist.github.com/anonymous/d35c982e95871f7acdc0a95175c65b72\n')
    f.write('\n')
    
    if len(results['error']['403']):
        f.write('\t403 Forbidden:\n')
        for domain in results['error']['403']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['503']):
        f.write('\t503 Service Unavailable:\n')
        for domain in results['error']['503']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['504']):
        f.write('\t504 Gateway Timeout:\n')
        for domain in results['error']['504']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['different_content']):
        f.write('\tDifferent content:\n')
        for domain in results['error']['different_content']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['incomplete_certificate_chain']) > 0:
        f.write('\tIncomplete certificate chain:\n')
        for domain in results['error']['incomplete_certificate_chain']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['invalid_certificate']) > 0:
        f.write('\tInvalid certificate:\n')
        for domain in results['error']['invalid_certificate']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['mixed_content']) > 0:
        f.write('\tMCB:\n')
        for domain in results['error']['mixed_content']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')

    if len(results['error']['no_working_url_known']) > 0:
        f.write('\nNo working URL known:\n')
        for domain in results['error']['no_working_url_known']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['other_ssl_error']) > 0:
        f.write('\tOther SSL error:\n')
        for domain in results['error']['other_ssl_error']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['redirect_to_http']) > 0:
        f.write('\tRedirects to HTTP:\n')
        for domain in results['error']['redirect_to_http']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['refused']) > 0:
        f.write('\tRefused:\n')
        for domain in results['error']['refused']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    if len(results['error']['timeout']) > 0:
        f.write('\tTimeout:\n')
        for domain in results['error']['timeout']:
            f.write('\t\t- ' + domain + '\n')
        f.write('\n')
    
    f.write('-->\n')
    
    f.write('<ruleset name=\"' + args.name + '\">\n')
    for domain in results['success']:
        f.write('\t<target host="%s" />\n' % (domain[0]))
        if len(domain) > 1:
            for test in domain[1:]:
                f.write('\t<test url="%s" />' % (test))
    
    f.write('\n')
    if not has_bad_domains:
        f.write('\t<securecookie host=".+" name=".+" />\n')
        f.write('\n')
        
    for rule in results['rules']:
        if rule[2] == True:
            f.write('\t<!-- The domain ' + rule[0] + \
            ' is redirected because the secure version sends an invalid redirect response. -->\n')
        f.write('\t<rule from="^http://%s/" to="%s" />\n' % (re.escape(rule[0]), rule[1]))
    if len(results['rules']) > 0:
        f.write('\n')
    f.write('\t<rule from="^http:" to="https:" />\n')
    f.write('</ruleset>')
    f.flush()
    f.close()

if __name__=='__main__':
    #domain, name, timeout, verbose
    ruleset_generator(parse_args())