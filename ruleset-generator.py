import argparse
import re
import requests
import subprocess
import sys
from Sublist3r import sublist3r as s3

def parser_error(errmsg):
    print("Usage: python3 "+sys.argv[0]+" [Options] use -h for help")
    print("Error: " + errmsg)
    exit()

def parse_args():
    # Parse the arguments
    parser = argparse.ArgumentParser(epilog = '\tExample: \r\npython3 ' + sys.argv[0] + " -d eff.org")
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
    hosts.extend(s3.main(domain, 30, False, None, not verbose, verbose, False))
    return hosts

#'h' stands for hosts
htimeout = []
hrefused = []
hbadcert = []
hinchain = []
hredirect = []
hsslerror = []

hsuccess = []
hdiffcont = []
hmixedcont = []

def main(domain, name, timeout, verbose):
    # Step 0: Validate input
    if not check_domain(domain):
        print("Error: Please enter a valid domain.")
        exit()
    
    if name == "":
        name = domain
    
    # Step 1: Find subdomains using sublist3r
    hosts = find_domains(domain, verbose)
    
    # Step 2: Sort out false positives
    hostsok = []
    for host in hosts:
        resp, resps = False, False
        try:
            resp = requests.get("http://" + host + '/', timeout=timeout, allow_redirects=True, headers={'User-Agent': 'HTTPSE-ruleset-generator STEP1. Internet security project https://github.com/Foorack/httpse-ruleset-generator.', 'Connection':'close'})
        except requests.exceptions.ConnectionError:
            ()
        except requests.exceptions.Timeout:
            ()
        
        try:
            resps = requests.get("https://" + host + '/', timeout=timeout, allow_redirects=True, headers={'User-Agent': 'HTTPSE-ruleset-generator STEP2. Internet security project https://github.com/Foorack/httpse-ruleset-generator.', 'Connection':'close'})
        except requests.exceptions.SSLError as err:
            msg = str(err)
            if "doesn't match" in msg:
                hbadcert.append(host)
                continue
            elif "CERTIFICATE_VERIFY_FAILED" in msg:
                hinchain.append(host)
                continue
            else:
                hsslerror.append(host)
                continue
        except requests.exceptions.Timeout:
            if resp == False: # Ignore if HTTP also didn't work
                continue
            htimeout.append(host)
            continue
        except requests.exceptions.RequestException:
            if resp == False: # Ignore if HTTP also didn't work
                continue
            hrefused.append(host)
            continue
        
        if verbose == True:
            print(host, resp, resps)
        
        if resp == False:
            hsuccess.append(host)                                   # Perfect, only HTTPS works
        else:
            hostsok.append([host, resp, resps])
    hosts = hostsok
    
    # Step 3: Check for SSL availability
    for host in hosts:
        if host[2].url.startswith("http://"):                      # Does HTTPS redirect to HTTP?
            hredirect.append(host[0])
        elif host[2].url.startswith("https://"):                   # Okay so HTTPS is still on HTTPS...
            if host[1].url.startswith("https://"):                  # Does HTTP redirect to HTTPS?
                hsuccess.append(host[0])                            # Perfect! Can't be wrong content then!
            else:                                                   # Oh so HTTP does not redirect to HTTPS, have to check content then
                if abs(len(host[2].content) - len(host[1].content)) < 250: # TODO: Update this checker
                    if host[2].content.decode('utf-8', 'ignore').find("src=\"http://") != -1 or host[2].content.decode('utf-8', 'ignore').find("type=\"text/css\" href=\"http://") != -1 or host[2].content.decode('utf-8', 'ignore').find("url(\"http://") != -1:
                        hmixedcont.append(host[0])
                    else:
                        hsuccess.append(host[0])
                else:
                    print(abs(len(host[2].content) - len(host[1].content)))
                    hdiffcont.append(host[0])
    
    # Step 4: Print results to output file
    _print_file(domain, name, hrefused, htimeout, hbadcert, hinchain,hsslerror, hredirect, hdiffcont, hmixedcont, hsuccess)
    
def _print_file(domain, name, hrefused, htimeout, hbadcert, hinchain,hsslerror, hredirect, hdiffcont, hmixedcont, hsuccess):
    f = open(domain + '.xml', 'w')
    f.write("<!--\n")
    f.write("\n")
    f.write("   Generator: HTTPSE-ruleset-generator v1.0\n")
    f.write("\n")
    
    if len(hrefused) > 0:
        f.write("   Refused:\n")
        for host in hrefused:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(htimeout) > 0:
        f.write("   Timeout:\n")
        for host in htimeout:
            f.write("       - " + host + "\n")
        f.write("\n")
    
    if len(hbadcert) > 0:
        f.write("   Wrong certificate:\n")
        for host in hbadcert:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(hinchain) > 0:
        f.write("   Incomplete certificate-chain:\n")
        for host in hinchain:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(hsslerror) > 0:
        f.write("   Other unknown SSL error:\n")
        for host in hsslerror:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(hredirect) > 0:
        f.write("   Redirects to HTTP:\n")
        for host in hredirect:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(hdiffcont) > 0:
        f.write("   Different content:\n")
        for host in hdiffcont:
            f.write("       - " + host + "\n")
        f.write("\n")
        
    if len(hmixedcont) > 0:
        f.write("   Mixed content:\n")
        for host in hmixedcont:
            f.write("       - " + host + "\n")
        f.write("\n")
    
    f.write("-->\n")
    
    f.write("<ruleset name=\"" + name + "\">\n")
    for host in hsuccess:
        f.write("   <target host=\"" + host + "\" />\n")
    f.write("\n")
    f.write("   <securecookie host=\".+\" name=\".+\" />\n")
    f.write("\n")
    f.write("   <rule from=\"^http:\" to=\"https:\" />\n")
    f.write("</ruleset>\n")

if __name__=="__main__":
    args = parse_args()
    domain = args.domain
    name = args.name
    timeout = args.timeout
    verbose = args.verbose
    verbose = (verbose or verbose is None)
    
    main(domain, name, timeout, verbose)