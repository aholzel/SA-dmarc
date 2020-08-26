#!/usr/bin/python
"""
Copyright 2018- Arnold Holzel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
##################################################################
# Author        : Arnold Holzel
# Creation date : 2018-05-08
# Description   : Script to do dmarc rua mail check and to do SPF record resolving.                 
#
# Version history
# Date          Version     Author      Type    Description
# 2018-05-28    1.0         Arnold              Initial version
# 2018-05-29    1.1         Arnold              Added some logging
# 2018-05-30    1.2         Arnold              Changed the dmarc_domain csv to be able to exclude domains from the spf lookup
#                                               domains with a exists: item in the spf record can't be resolved.    
# 2018-06-25    1.3         Arnold              Disabled some super debug log
# 2020-08-25    1.4.0       Arnold      [FIX]   Fixed a problem when there where multiple A records for a domain, only 1 was returned
#                                       [FIX]   Fixed single IP notation in the lookup, it is now written as a /32 to be able to do CIDR lookups
#                                       [ADD]   Added lookups for AAAA records. 
#
##################################################################
import subprocess, shlex, re, csv, sys, argparse, os
from threading import Timer

import classes.splunk_info as si
import classes.custom_logger as c_logger

script_dir = os.path.dirname(os.path.abspath(__file__))                                     # The directory of this script

resolve_timeout = 2

# setup the script logger
logger = c_logger.Logger()
log_level = 10 # set the default log level to INFO
temp_logger = logger.logger_setup(name="temp_logger", level=log_level)

# Setup the script arguments.
options = argparse.ArgumentParser(epilog='Example: %(prog)s  -c spf')
options.add_argument("-c", "--check", help="check type; spf OR dmarc")
options.add_argument("--sessionKey", help="The splunk session key to use")
args = options.parse_args()

txt_lookup_type = args.check

# Check if there is a Splunk session key available
if args.sessionKey is None or len(args.sessionKey) == 0:
    sessionKey = sys.stdin.readline().strip()
    temp_logger.debug("Splunk SessionKey provided by stdin")
    # Super debug:
    #temp_logger.debug("Splunk SessionKey provided by stdin. SessionKey: " + str(sessionKey))
elif len(args.sessionKey) != 0:
    sessionKey = args.sessionKey
    temp_logger.debug("Splunk SessionKey provided by command line argument")
    # Super debug:
    #temp_logger.debug("Splunk SessionKey provided by command line argument. SessionKey: " + str(sessionKey))
else:
    temp_logger.critical("No Splunk SessionKey provided. Exit script")
    sys.exit(1)

# Connect with Splunk to get all the info needed
splunk_info = si.Splunk_Info(sessionKey)
splunk_paths = splunk_info.give_splunk_paths(script_dir)

# Try to get the log level from the config file.
try:
    log_level_config = splunk_info.get_config(str(splunk_paths['app_name'].lower()) + ".conf", 'main', 'log_level')
except Exception:
    log_level = 20
    script_logger.exception("Something went wrong fetching the log_level from the config file. Traceback: ")
else:
    log_level = log_level_config

script_logger = logger.logger_setup(name="script_logger", level=log_level)    


# Set all the directory's based on the directory this script is in.
app_root_dir = splunk_paths['app_root_dir']                                             # The app root directory
log_root_dir = os.path.normpath(app_root_dir + os.sep + "logs")                         # The root directory for the logs
lookup_dir = os.path.normpath(app_root_dir + os.sep + "lookups")                        # The root directory for the lookups

# Set the csv file names and the fields they contain.
dmarc_csv_file = os.path.normpath(lookup_dir + os.sep + "dmarc_email_domains.csv")
dmarc_csv_fields = [ 'domain', 'spf_lookup_script' ]
spf_csv_file = os.path.normpath(lookup_dir + os.sep + "spf_mailservers.csv")
spf_csv_fields = [ 'ptr', 'ip', 'mail_server_group' ]

# Create al the directory's if they don't exist
if not os.path.exists(log_root_dir):
    os.makedirs(log_root_dir)
if not os.path.exists(lookup_dir):
    os.makedirs(lookup_dir)

# By default nslookups can take up to 30 seconds if there is no entry for the given request.
# This is not something that can be changed. That would mean that if you need to do a lot of
# lookups that it could take quite some time. To counter this we define two method's 
# one to run a proces (nslookup in this case) and one to kill it if it runs longer than x sec
def kill_process(process, timeout):
    timeout["value"] = True
    process.kill()

def run_process(cmd, timeout_sec):
    process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timeout = {"value": False}
    timer = Timer(timeout_sec, kill_process, [process, timeout])
    timer.start()
    stdout, stderr = process.communicate()
    timer.cancel()
    
    # return the process returncode, whether or not we hit the set timeout, stdout, stderr
    return process.returncode, timeout["value"], stdout.decode("utf-8"), stderr.decode("utf-8")

def search_dns_record(domain, record_type, text_sub_record=""):
    global script_logger
    record_type = record_type.lower()
    
    # Do an nslookup for the reqeusted domain and record type 
    output = run_process("nslookup -q=" + str(record_type) + " " + str(domain), resolve_timeout)
    
    # if the process returncode was 0 (zero) we had a clean exit of the nslookup process and we can
    # continue to process the results. Every event will give back a different line and below that
    # line is parsed based on the requested type. If a TXT record was requested look for the 
    # specific TXT record.
    if str(output[0]) == "0":
        if str(record_type) == "ptr":
            regex_search = "(?i)name\s*(?:\=|\:)\s*([^\s]*)"
        elif str(record_type) == "a" or str(record_type) == 'aaaa':
            regex_search = "(?si)answer\:.*address(?:es\s*|\s*)(?:\=|\:)\s*(.*)"
        elif str(record_type) == "mx":
            regex_search = "(?i)exchanger\s+(?:\=|\:)(?:\s+\d+\s+|\s+)(.*)"
        elif str(record_type) == "txt":
            if str(text_sub_record) == "dmarc":
                regex_search = "(?i)text\s*(?:\=|\:)\s*\"(v\=dmarc[^\"]*)"
            elif str(text_sub_record) == "spf":
                regex_search = "(?i)text\s*(?:\=|\:)\s*\"(v\=spf[^\"]*)"
        
        # When a MX record is requested, in most of the times you get multiple responses the below 
        # "findall" regex takes care of that.
        if regex_search:
            if str(record_type) == "mx" or str(record_type) == "a" or str(record_type) == 'aaaa':
                return_value = re.findall(regex_search, output[2])
            else:
                search = re.search(regex_search, output[2])
                return_value = search.group(1)
            script_logger.debug("Searched DNS record: " + str(record_type) + ", found value(s): " + str(return_value))
        else:
            return_value = output[2]
            script_logger.error("Unexpected response from nslookup, response: " + str(return_value))
    else:
        return_value = "No " + str(record_type) + " record found for " + str(domain)
        script_logger.error(str(return_value))
        
    return return_value

def make_binary(input):
    if input is False or str(input) == "0" or input.lower() == "false" or input.lower() == "f":
        output = 0
    elif input is True or str(input) == "1" or input.lower() == "true" or input.lower() == "t":
        output = 1
    else:
        output = 0
    
    return output
        
with open(dmarc_csv_file, "rb") as csvfile:
    domainreader = csv.DictReader(csvfile)
    
    for row in domainreader:
        script_logger.debug("Current Row in csv: " + str(domainreader.line_num) + "; data: " + str(row))
        maildomain =  row['domain']
        spf_lookup_script_raw = row['spf_lookup_script']
        spf_lookup_script = make_binary(spf_lookup_script_raw)
        script_logger.debug("Current maildomain: " + str(maildomain) + ", this script should do the lookup for this domain: " +  str(spf_lookup_script_raw) + " (raw input), " + str(spf_lookup_script) + " (normalised input)")
        
        if txt_lookup_type == "dmarc":
            script_logger.debug("===== Start DMARC checks =====")
            dmarc_domain = "_dmarc." + str(maildomain)
            query_dmarc = search_dns_record(dmarc_domain, "txt", "dmarc")

            search_rua = re.search("rua\=mailto\:([^\\\;]*)", query_dmarc)

            if search_rua:
                rua_mailto = str(search_rua.group(1))
                search_rua_maildomain = re.search("\@([^\s]*)", rua_mailto)
                # regex to find the domain in the email adres 
                # example.net in mail.example.net
                search_rua_domain = re.search("([A-Za-z0-9-]+\.([A-Za-z]{3,}$|[A-Za-z]{2}\.[A-Za-z]{2}$|[A-za-z]{2}$))", str(search_rua_maildomain.group(1)))
                rua_mail_domain = str(search_rua_domain.group(1))
                
                # if the rua mail domain is not equal to the domain check if there is a dns record for the rua mail domain
                # and report back with the results
                if rua_mail_domain != maildomain:
                    dmarc_report_domain = str(maildomain) + "._report._dmarc." + str(rua_mail_domain)

                    report_domain_output = search_dns_record(dmarc_report_domain, "txt", "dmarc")
                    
                    if report_domain_output.lower().startswith("v=dmarc1"):
                        script_logger.info(str(maildomain) + ": dmarc record is RFC7489 compliant configured")
                    else:
                        script_logger.warning(str(maildomain) + ": is not RFC7489 compliant configured " + str(report_domain_output))
                else:
                    script_logger.info(str(maildomain) + ": dmarc record is RFC7489 compliant configured")
            else:
                script_logger.warning("No rua email found for domain " + str(maildomain) + " in DNS record: " + str(query_dmarc))
        elif txt_lookup_type == "spf" and spf_lookup_script == 1:
            # Open the SPF lookup file and remove the records for this domain so we can put in the new ones later.
            
            with open(spf_csv_file, "rb") as spf_csv_read:
                # First read everything that is currently in the csv into a list 
                spf_reader = list(csv.DictReader(spf_csv_read))
           
            with open(spf_csv_file, "w") as spf_csv_write:
                writer = csv.DictWriter(spf_csv_write, fieldnames=spf_csv_fields)
                writer.writeheader()
                
                for row in spf_reader:
                    # Check each row and see if the maildomain is something we will lookup again later, if so don't write it back 
                    # to the csv file.
                    if row['mail_server_group'] != maildomain:
                        writer.writerow( { 'ptr': row['ptr'], 'ip': row['ip'], "mail_server_group": row['mail_server_group'] } )
                    
            script_logger.debug("===== Start SPF checks =====")
            
            query_spf = search_dns_record(maildomain, "txt", "spf")
            
            # regex to search for the spf record
            search_spf = re.search("v\=spf1\s+(.*)", query_spf)
            # Split the given SPF result in a list to loop through
            spf_list = list(search_spf.group(1).split())
            
            for spf_item in spf_list:
                # Loop through the list and check what kind of option is in there
                spf_item = spf_item.lower()
                
                if str(spf_item).startswith("include:") or str(spf_item).startswith("+include:"):
                    script_logger.debug("Found \"include\" record: " + str(spf_item) + ", resolve again")
                    txt, recheck_spf = spf_item.split(":")
                    
                    query_spf = search_dns_record(recheck_spf, "txt", "spf")
                    search_spf = re.search("v\=spf1\s+(.*)", query_spf)
                    spf_list_append = list(search_spf.group(1).split())
                    
                    spf_list[spf_list.index(spf_item)] = "-"
                    spf_list += spf_list_append
                elif str(spf_item).startswith("a:") or str(spf_item).startswith("+a:") or spf_item == "a" or spf_item == "+a":
                    script_logger.debug("Found \"a\" record: " + str(spf_item) + ", resolving....")
                    if spf_item.startswith("a:"):
                        txt, lookup_a = spf_item.split(":")
                    else:
                        lookup_a = maildomain
                        
                    a_record = search_dns_record(lookup_a, "a")
                    
                    spf_list[spf_list.index(spf_item)] = "-"
                    spf_list_append = [a_record.strip(".")]
                    spf_list += spf_list_append
                elif str(spf_item) == "mx" or str(spf_item) == "+mx":
                    script_logger.debug("Found \"mx\" record: " + str(spf_item) + ", resolving....")
                    mx_record = search_dns_record(maildomain, "mx")
                    spf_list_append = []
                    
                    # A mx lookup can return multiple results so find every one of them.
                    for mx in mx_record:
                        # Do a 'A' and a 'AAAA' lookup for the given MX record.
                        mx_ip_a     = search_dns_record(mx, 'a')
                        mx_ip_aaaa  = search_dns_record(mx,'aaaa')
                        
                        if mx_ip_a:
                            for ip_a in mx_ip_a:
                                # it is a ipv4 address so prefix it with ipv4 and put the /32 behind it for a CIDR lookup in splunk
                                mx_ip = 'ip4:' + str(ip_a.replace('\n','')) + '/32'
                                spf_list_append.append(mx_ip.strip("."))
                        
                        if mx_ip_aaaa:
                            for ip_aaaa in mx_ip_aaaa:
                                # it is a ipv6 address so prefix it with ipv6 and put the /128 behind it for a CIDR lookup in splunk
                                mx_ip = 'ip6:' + str(ip_aaaa.replace('\n','')) + '/128'
                                spf_list_append.append(mx_ip.strip("."))

                        
                    spf_list[spf_list.index(spf_item)] = "-"
                    spf_list += spf_list_append
                elif str(spf_item) == "-all" or str(spf_item) == "~all" or str(spf_item) == "?all":
                    script_logger.debug("Found record end: " + str(spf_item))
                    spf_list[spf_list.index(spf_item)] = "-"
                elif str(spf_item).startswith("exists:") or str(spf_item).startswith("+exists:"):
                    script_logger.debug("Found \"exists\" record: " + str(spf_item) + ", this cannot be resolved so skipping.")
                    spf_list[spf_list.index(spf_item)] = "-"
                elif str(spf_item).startswith("redirect=") or str(spf_item).startswith("+redirect="):
                    script_logger.debug("Found \"redirect\" record: " + str(spf_item) + ", resolve again.")
                    txt, recheck_spf = spf_item.split("=")
                    
                    query_spf = search_dns_record(recheck_spf, "txt", "spf")
                    search_spf = re.search("v\=spf1\s+(.*)", query_spf)
                    spf_list_append = list(search_spf.group(1).split())
                    
                    spf_list[spf_list.index(spf_item)] = "-"
                    spf_list += spf_list_append
                elif str(spf_item).startswith("ip4:") or str(spf_item).startswith("+ip4:") or str(spf_item).startswith("ip6:") or str(spf_item).startswith("+ip6:"):
                    script_logger.debug("Found \"ip\" record: " + str(spf_item))
                else:
                    script_logger.error("Found unknown record: " + str(spf_item))
                    spf_list[spf_list.index(spf_item)] = "-"
                    
            spf_list = list(set(spf_list))
            
            if "-" in spf_list:
                # Remove all list items that contain only a "-"
                spf_list.remove("-")
            
            # remove ip4: and ip6: prefixes
            for spf_item in spf_list:
                if spf_item.startswith("ip4:") or spf_item.startswith("ip6:"):
                    new_item = spf_item[4:]
                    spf_list[spf_list.index(spf_item)] = str(new_item)
        
            # write everything to the lookup file
            if domainreader.line_num == 2:
                file_open_mode = "w"
            else:
                file_open_mode = "a"
                
            with open(spf_csv_file, file_open_mode) as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=spf_csv_fields)
                if file_open_mode == "w":
                    writer.writeheader()
                
                for spf_item in spf_list:
                    script_logger.debug("Item to write to csv: " + str(spf_item))
                    if spf_item[-3:-2] == "/" or spf_item[-4:-3] == "/":
                        ptr = "SPF_CIDR-" + str(spf_item)
                    else:
                        ptr_lookup = search_dns_record(spf_item, "ptr")
                        ptr = "SPF_PTR-" + str(ptr_lookup)
                    
                    writer.writerow( { 'ptr': ptr.strip("."), 'ip': spf_item, "mail_server_group": maildomain } )
        else:
            pass
            