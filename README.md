# SA-dmarc
## Description
Splunk app for visualization of ingested DMARC RUA mails. This app contains a couple of dashboards to visualize the DMARC RUA data after it has been processed by the TA-dmarc (see https://github.com/aholzel/TA-dmarc). 

## Installation
The app needs to be installed on the Splunk Searchhead

## Configuration

### Macros
The app contains a couple of Splunk macro's and at leased one of them needs to be checked. 

**dmarc_log**   : Macro that needs to contain the index and sourcetype of the processed rua files. [default: *index=dmarc (sourcetype=dmarc OR sourcetype=dmarc:json)* ]  
**external_dns_log** : Marco that needs to contain the index and sourcetype of the external DNS logs if you also want to make use of the "Advanced SPF" options. [default: *index=network sourcetype=named* ]

### Scripts
The app contains a script to do the SPF record lookup and fill the "spf_mailservers.csv" lookup file. This script is disabled by default, because there are some requirements for this to work.
1. The SPF record can not contain the "exists" options
2. The Splunk Searchhead needs to be able to do DNS lookups for SPF records, so if the Searchhead can only do lookups against the internal DNS and that DNS doesn't contain the SPF records the script won't function correct.

## Content
### Dashboards
- **DMARC overview** : Main dashboard for the visualization of the data. The dashboard has different options to group the data. And also has the option to resolve the source IP's if that info is not already in the logs (please note that this can cause load times to increase)
- **DMARC cluster map** : Dashboard with a map of the world and a visualization of where the mails where send from and whether or not the mails where send from a system that is in your SPF record.
- **DMARC mails by source results** : Quick overview of the status of the emails that where send.
- **DMARC RFC info** : Dashboard with the (in my opinion) important parts of the DMARC RFC7489, as well as an explanation of how the app determines whether the right policy has been applied.
- **SPF RFC info** : Dashboard with the (in my opinion) important parts of the SPF RFC7208.
- **SPF resolving** : Dashboard to see who is trying to send mails from your maildomains. This requires some "advanced SPF" (see the SPF RFC info dashboard) and that the logs of the external DNS servers is available in Splunk.

### Lookups
- **dmarc_email_domains.csv** : Lookup with a list of the maildomains that are in use. The lookup contains 2 columns
  * domain : The mail domain
  * spf_lookup_script : Whether or not the script needs to do the lookup of the SPF record for the given domain. Possible values are true or false if nothing is provided false will be assumed.
- **spf_mailservers.csv** : Lookup with the fully-written SPF record. The lookup contains 3 columns
  * ptr : The PTR or description of the IP OR CIDR
  * ip : The IP or CIDR provided in the SPF record
  * mail_server_group : The maildomain
- **spf_resolving_filter.csv** : Lookup to filter out known false positives from the SPF Resolving dashboard. The lookup contains 5 columns
  * sending_server_ip : The IP of the sending server as it appears in the DNS lookup
  * sending_server_helo : The HELO of the sending server as it appears in the DNS lookup (supports wildcard)
  * sending_mail_domain : The maildomain as it appears in the DNS lookup (supports wildcard)
  * recieving_server_ip : The IP of the mail server that is recieving the "mails" and doeing the lookups
  * note : A note to add why this row was added.
  
### Macros
- **dmarc_log**   : Macro that needs to contain the index and sourcetype of the processed rua files.
- **external_dns_log** : Marco that needs to contain the index and sourcetype of the external DNS logs if you also want to make use of the "Advanced SPF" options.
- **dmarc_domains(1)** : Macro that merges the "dmarc_email_domains" lookup and the "cim_corporate_email_domain_lookup" if available. The required argument is used to manipulate the output table. 
- **spf_dkim_dmarc_checks** : Macro that contains the SPF/DKIM/DMARC checks and determines if the correct policy is applied.

### Savedsearches
- **DMARC domains - Lookup Gen** : Search that generates the "dmarc_email_domains.csv" based on the "dmarc_domains(1)" macro.
