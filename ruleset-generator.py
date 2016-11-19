import argparse
import functools
import re
import requests
import socket
import subprocess
import sys
from Sublist3r import sublist3r as s3

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

#'h' stands for hosts
htimeout = []
hrefused = []
hbadcert = []
hbadcerttmp = []
hinchain = []
hredirect = []
hredirecttmp = []
hsslerror = []

rules = []
hsuccess = []
hdiffcont = []
hmixedcont = []

def test_domain(host):
    
    # Check if DNS exists to save time
    try:
        socket.gethostbyname(host)
    except socket.gaierror: # DNS does not exist
        return
    
    resp, resps = None, None
    try:
        resp = requests.get("http://" + host + '/', timeout=timeout, allow_redirects=True, headers={'User-Agent': 'HTTPSE-ruleset-generator STEP1. Internet security project https://github.com/Foorack/httpse-ruleset-generator.', 'Connection':'close'})
    except requests.exceptions.ConnectionError:
        ()
    except requests.exceptions.Timeout or socket.timeout:
        ()
    
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
                rules.append([host, resp.url])
            else:
                if resp.url.startswith("http://www"):
                    hbadcerttmp.append([host, resp.url[11:]])
                    return # TODO: double check this ^
                    
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
    
    # Check if HTTP redirects to the same domain with HTTPS
    if resp.url.startswith("https://" + host):
        hsuccess.append(host)
        return
    
    # It does not redirect to itself with HTTPS, maybe it redirect to itself with HTTP?
    if resp.url.startswith("http://" + host):
        hsuccess.append(host)
        return
    
    # HTTP redirects to another domain
    
    # Lets check if HTTPS redirects to another HTTPS?
    if resps.url.startswith("https://"):
        hsuccess.append(host)
        return
    
    # Lets check if HTTPS redirects to HTTP?
    if resps.url.startswith("http://"):
        hredirecttmp.append([host, resps.url[7:]])
        return
    
    if resp.url.startswith("http://"):
        hredirecttmp.append([host, resps.url[7:]])
    else:
        rules.append([host, resp.url])
    
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
                    hsuccess.append(hr[0])
                    return True
            return False
        if not dd1():
            hredirect.append(hr[0])
    
    # 
    print(hbadcerttmp)
    for hr in hbadcerttmp:
        def dd2():
            for host in hsuccess:
                if hr[1].startswith(host):
                    rules.append([hr[0], "https://" + hr[1]])
                    return True
            return False
        if not dd2():
            hbadcert.append(hr[0])
    
    # Final fixes
    for rule in rules:
        hsuccess.append(rule[0])
    
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
    if len(hrefused) > 0 or len(htimeout) > 0 or len(hbadcert) > 0 or len(hinchain) > 0 or len(hsslerror) > 0 or len(hredirect) > 0 or len(hdiffcont) > 0 or len(hmixedcont) > 0:
        f.write("<!--\n")
        f.write("\n")
    #f.write("    Generator: HTTPSE-ruleset-generator v1.0\n")
    #f.write("\n")
    
    if len(hrefused) > 0:
        f.write("    Refused:\n")
        for host in hrefused:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(htimeout) > 0:
        f.write("    Timeout:\n")
        for host in htimeout:
            f.write("        - " + host + "\n")
        f.write("\n")
    
    if len(hbadcert) > 0:
        f.write("    Invalid certificate:\n")
        for host in hbadcert:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(hinchain) > 0:
        f.write("    Incomplete certificate-chain:\n")
        for host in hinchain:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(hsslerror) > 0:
        f.write("    Other unknown SSL error:\n")
        for host in hsslerror:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(hredirect) > 0:
        f.write("    Redirects to HTTP:\n")
        for host in hredirect:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(hdiffcont) > 0:
        f.write("    Different content:\n")
        for host in hdiffcont:
            f.write("        - " + host + "\n")
        f.write("\n")
        
    if len(hmixedcont) > 0:
        f.write("    MCB:\n")
        for host in hmixedcont:
            f.write("        - " + host + "\n")
        f.write("\n")
    
    if len(hrefused) > 0 or len(htimeout) > 0 or len(hbadcert) > 0 or len(hinchain) > 0 or len(hsslerror) > 0 or len(hredirect) > 0 or len(hdiffcont) > 0 or len(hmixedcont) > 0:
        f.write("-->\n")
    
    f.write("<ruleset name=\"" + name + "\">\n")
    for host in hsuccess:
        f.write("    <target host=\"" + host + "\" />\n")
    f.write("\n")
    f.write("    <securecookie host=\".+\" name=\".+\" />\n")
    f.write("\n")
    for rule in rules:
        f.write("    <rule from=\"^http://" + re.escape(rule[0]) + "/\" to=\"" + rule[1] + "\" />\n")
    if len(rules) > 0:
        f.write("\n")
    f.write("    <rule from=\"^http:\" to=\"https:\" />\n")
    f.write("</ruleset>\n")
    f.flush()

if __name__=="__main__":
    args = parse_args()
    domain = args.domain
    name = args.name
    timeout = args.timeout
    verbose = args.verbose
    verbose = (verbose or verbose is None)
    
    main(domain, name, timeout, verbose)