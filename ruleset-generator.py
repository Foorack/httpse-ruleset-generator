import argparse
import functools
import re
import requests
import socket
import ssl
import subprocess
import sys
from Sublist3r import sublist3r as s3

#'h' stands for hosts
htimeout = []
hrefused = []
hbadcert = []
hbadcerttmp = []
hinchain = []
hredirect = []
hredirecttmp = []
hsslerror = []
h503 = []
h401 = []
h403 = []

rules = []
hsuccess = []
hdiffcont = []
hmixedcont = []

def is_bad_domains():
    return len(hrefused) > 0 or len(htimeout) > 0 or len(hbadcert) > 0 or len(hinchain) > 0 or len(hsslerror) > 0 or len(hredirect) > 0 or len(hdiffcont) > 0 or len(hmixedcont) > 0 or len(h401) > 0 or len(403) > 0 or len(503) > 0

def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    exit()

def parse_args():
    # Parse the arguments
    parser = argparse.ArgumentParser(epilog = '    Example: \r\npython3 ' + sys.argv[0] + " -d eff.org")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain to generate ruleset about, TLD, do not include www", required=True)
    parser.add_argument('-n', '--name', help='Label the ruleset with a custom name, for example "Electronic Frontier Foundation"',type=str, default='')
    parser.add_argument('-t', '--timeout', help='Define timeout value, this might be neccesary on slower internet connections', type=int, default=8)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime',nargs='?', default=False)
    return parser.parse_args()

def check_domain(domain):
    domain_check = re.compile("^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    return domain_check.match(domain)

def find_domains(domain, verbose):
    hosts = [domain]
    hosts.extend(s3.main(domain, 30, False, None, not verbose, verbose, False, 'Baidu,Yahoo,Google,Bing,Ask,Netcraft,Virustotal,SSL'))
    return hosts

def check_chrome_301_header_trunc(resps):
    for hre in resps.history:
        if hre.status_code == 301 or hre.status_code == 302: # do 302 as well :)
            CRLF = "\r\n"
            
            addr = "/"
            if(len(hre.url.split("/")) > 3)
                addr = hre.url[(7 + len(hre.url.split("/")[2])):]
            
            request = [
                "GET " + addr + " HTTP/1.1",
                "Host: " + hre.url.split("/")[2],
                "Connection: Close",
                "",
                "",
            ]
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            wrappedSocket = ssl.wrap_socket(sock)

            wrappedSocket.connect((hre.url.split("/")[2], 443))
            wrappedSocket.send(CRLF.join(request).encode('utf-8'))
            # Get the response (in several parts, if necessary)
            response = wrappedSocket.recv(4096)
            
            wrappedSocket.close()
            
            # HTTP headers will be separated from the body by an empty line
            header_data, ll, body = response.decode('utf-8').partition(CRLF + CRLF)
            
            return ll != '\r\n\r\n'
    return False
    
# https://github.com/jeremyn/Sublist3r/blob/09a2b9cdaf020a7dac6701765a846807ef6db814/sublist3r.py#L82
def subdomain_cmp(d1, d2):
    """cmp function for subdomains d1 and d2.
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
    """
    d1 = d1.split('.')[::-1]
    d2 = d2.split('.')[::-1]

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

def test_domain(host):
    # Check if DNS exists to save time
    try:
        socket.gethostbyname(host)
    except socket.gaierror: # DNS does not exist
        return
    
    # Do HTTP
    resp, resps = None, None
    try:
        resp = requests.get("http://" + host + '/', timeout=timeout, allow_redirects=True, headers={'User-Agent': 'HTTPSE-ruleset-generator STEP1. Internet security project https://github.com/Foorack/httpse-ruleset-generator.', 'Connection':'close'})
    except requests.exceptions.ConnectionError:
        ()
    except requests.exceptions.Timeout or socket.timeout:
        ()
    
    # Do HTTPS
    try:
        resps = requests.get("https://" + host + '/', timeout=timeout, allow_redirects=True, headers={'User-Agent': 'HTTPSE-ruleset-generator STEP2. Internet security project https://github.com/Foorack/httpse-ruleset-generator.', 'Connection':'close'})
    except requests.exceptions.SSLError as err:
        msg = str(err)
        if "doesn't match" in msg:
            if resp == None:
                hbadcert.append(host)
                return
                
            # Check if HTTP redirects to a working HTTPS website
            if resp.url.startswith("https://"):
                rules.append([host, resp.url, 0])
            else:
                if len(resp.history) > 0:
                    hbadcerttmp.append([host, resp.url[7:]])
                else:
                    hbadcert.append(host)
            return
        elif "CERTIFICATE_VERIFY_FAILED" in msg:
            hinchain.append(host)
            return
        else:
            hsslerror.append(host)
            return
    except requests.exceptions.Timeout or socket.timeout:
        if resp == None: # Ignore if HTTP also didn't work
            return
        htimeout.append(host)
        return
    except requests.exceptions.RequestException:
        if resp == None: # Ignore if HTTP also didn't work
            return
        hrefused.append(host)
        return
    
    if verbose == True:
        print(host, resp, resps)
    
    if resp == None:
        hsuccess.append(host) # Perfect, only HTTPS works
        return
    
    # ...
    # At this point we know HTTPS works fine and that HTTP responds
    # ...
    
    if resps.status_code == 401:
        h401.append(host)
        return
    if resps.status_code == 403:
        h403.append(host)
        return
    if resps.status_code == 503:
        h503.append(host)
        return
    
    # Check if HTTP redirects to the same domain with HTTPS
    if resp.url.startswith("https://" + host):
        hsuccess.append(host)
        return
    
    # It does not redirect to itself with HTTPS, maybe it redirect to itself with HTTP?
    if resp.url.startswith("http://" + host):
        hsuccess.append(host)
        return
    
    # HTTP redirects to another domain
    
    # Check Chrome 301 trunc header issue
    e301 = False
    if len(resps.history) > 0:
        e301 = check_chrome_301_header_trunc(resps)
    
    # Lets check if HTTPS redirects to another HTTPS?
    if resps.url.startswith("https://"):
        if e301:
            rules.append([host, resps.url, 1])
        else:
            hsuccess.append(host)
        return
    
    # Lets check if HTTPS redirects to HTTP?
    if resps.url.startswith("http://"):
        hredirecttmp.append([host, resps.url[7:], e301])
        return
    
    if resp.url.startswith("http://"):
        hredirecttmp.append([host, resps.url[7:], e301])
    else:
        rules.append([host, resp.url, 0])
    
    return

def main(domain, name, timeout, verbose):
    # Step 0: Validate input
    if not check_domain(domain):
        print("Error: Please enter a valid domain.")
        exit()
    
    if name == "":
        name = domain
    
    # Step 1: Find subdomains using sublist3r
    hosts = find_domains(domain, verbose)
    
    # Step 2: Test all found domains
    for host in hosts:
        test_domain(host)
        
    # Check if HTTPS redirects to a HTTP site which we already redirect to HTTPS
    print(hredirecttmp)
    for hr in hredirecttmp:
        def dd1():
            for host in hsuccess:
                if hr[1].startswith(host):
                    if hr[2]:
                        rules.append([hr[0], hr[1], 1]) # 301 bug w/ chrome
                    else:
                        hsuccess.append(hr[0])
                    return True
            return False
        if not dd1():
            hredirect.append(hr[0])
    
    # Check if hosts with bad cert HTTP-redirect to a good host
    print(hbadcerttmp)
    for hr in hbadcerttmp:
        def dd2():
            for host in hsuccess:
                if hr[1].startswith(host):
                    rules.append([hr[0], "https://" + hr[1], 0])
                    return True
            return False
        if not dd2():
            hbadcert.append(hr[0])
    
    # Final fixes
    for rule in rules:
        hsuccess.append(rule[0])
    
    # Sort domains the way we want it
    hsuccess1 = sorted(
            hsuccess,
            key=functools.cmp_to_key(subdomain_cmp),
    )
    hbadcert1 = sorted(
            hbadcert,
            key=functools.cmp_to_key(subdomain_cmp),
    )
    
    # Step 3: Print results to output file
    f = open(domain + '.xml', 'w')
    if is_bad_domains():
        f.write("<!--\n")
        f.write("\n")
    #f.write("\tGenerator: HTTPSE-ruleset-generator v1.0\n")
    #f.write("\n")
    
    if len(h401) > 0:
        f.write("\t401 Unauthorized:\n")
        for host in h401:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
    
    if len(h403) > 0:
        f.write("\t403 Forbidden:\n")
        for host in h403:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(h503) > 0:
        f.write("\t503 Service Unavailable:\n")
        for host in h503:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
    
    if len(hrefused) > 0:
        f.write("\tRefused:\n")
        for host in hrefused:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(htimeout) > 0:
        f.write("\tTimeout:\n")
        for host in htimeout:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
    
    if len(hbadcert) > 0:
        f.write("\tInvalid certificate:\n")
        for host in hbadcert:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(hinchain) > 0:
        f.write("\tIncomplete certificate-chain:\n")
        for host in hinchain:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(hsslerror) > 0:
        f.write("\tOther unknown SSL error:\n")
        for host in hsslerror:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(hredirect) > 0:
        f.write("\tRedirects to HTTP:\n")
        for host in hredirect:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(hdiffcont) > 0:
        f.write("\tDifferent content:\n")
        for host in hdiffcont:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
        
    if len(hmixedcont) > 0:
        f.write("\tMCB:\n")
        for host in hmixedcont:
            f.write("\t\t- " + host + "\n")
        f.write("\n")
    
    if is_bad_domains():
        f.write("-->\n")
    
    f.write("<ruleset name=\"" + name + "\">\n")
    for host in hsuccess:
        f.write("\t<target host=\"" + host + "\" />\n")
    
    f.write("\n")
    if is_bad_domains():
        f.write("\t<securecookie host=\".+\" name=\".+\" />\n")
        f.write("\n")
        
    for rule in rules:
        if rule[2] == 1:
            f.write("\t<!-- The domain " + rule[0] + " is redirected because the secure version sends an invalid redirect response. -->\n")
        f.write("\t<rule from=\"^http://" + re.escape(rule[0]) + "/\" to=\"" + rule[1] + "\" />\n")
    if len(rules) > 0:
        f.write("\n")
    f.write("\t<rule from=\"^http:\" to=\"https:\" />\n")
    f.write("</ruleset>")
    f.flush()

if __name__=="__main__":
    args = parse_args()
    domain = args.domain
    name = args.name
    timeout = args.timeout
    verbose = args.verbose
    verbose = (verbose or verbose is None)
    
    main(domain, name, timeout, verbose)