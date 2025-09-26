# CHANGELOG
This file will contain the changes to the script files. In the script files you will only find th current major version change log. The file is split up in two parts, to make it easier to find the latest changes. The top part contains the latest changes per script and in general for the app. The bottom part contains all the changes.

# Latest version:
## General app changes
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2021-05-06 | 4.1.0   | Arnold  | **[FIX]** Macro missing argument in the `dmarc_overview` dashboard. <br />**[MOD]** Dashboard version numbers. 

## dmarc_spf_check.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2021-05-06 | 2.0.0   | Arnold  | **[MOD]** Changes to make the script python3 compatible<br />**[MOD]** Changed the way dns lookups are done, from now on pythonDNS is used

# Version history
## General app changes
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| -          | 1.0     | Arnold  | **[NEW]** Initial version
| -          | 1.1     | Arnold  | **[FIX]** bug fixes
| 2017-04    | 1.2     | Arnold  | **[FIX]** dashboard changes
| 2017-04    | 1.3     | Arnold  | **[FIX]** dashboard changes
| 2017-04    | 1.4     | Arnold  | **[ADD]** Added macro for index and sourcetype
| 2017-05-15 | 1.5     | Arnold  | **[ADD]** Added macro for merge of lookups, changes to the report dashboard.
| 2017-05-18 | 1.6     | Arnold  | **[ADD]** Added overview dashboard
| 2017-05-22 | 1.7     | Arnold  | **[MOD]** Change in the overview dashboard so that the policy's are now updated based on the <br />selected option.
| 2017-06-14 | 2.0     | Arnold  | **[NEW]** Made an autoextract regex for the field extraction<br /> **[MOD]** Changed the dashboards to use the new field names
| 2017-06-22 | 2.1     | Arnold  | **[MOD]** Changed the "spf_mailservers.csv" lookup table content, in the last column you now need to <br />place the domain the mail server is for (where the spf record is set) <br /> **[MOD]** Changed the Cluster map dashboard to use handle the new lookup layout.
| 2017-11-24 | 2.2     | Arnold  | **[MOD]** Changed the field extracts, removed all existing and made an "auto" extract transform based <br />on the new log format.<br /> **[MOD]** Made the lookups case insensitive <br /> **[ADD]** Added the SPF scope to the dmarc_report dashboard
| 2017-12-05 | 2.3     | Arnold  | **[ADD]** Added dashboard "DMARC mails by source & results" 
| 2018-05-23 | 3.0     | Arnold  | **[ADD]** Created script to check dmarc implementation and do a SPF record lookup to fill the lookup <br /> **[ADD]** Added macro's for the SPF/DKIM/DMARC checks <br /> **[ADD]** Added RFC info dashboard for SPF and DMARC with some of the important parts of the RFC <br />**[ADD]** Added dashboard and marco for advanced SPF info <br /> **[ADD]** Added more group options in the overview dashboard
| 2018-05-30 | 3.1     | Arnold  | **[ADD]** Added new column to the dmarc_email_domains.csv to point out if this domain needs to be <br />resolved by the spf lookup script -Changed the dmarc_domains macro to handle the new column <br /> **[MOD]** Changed the dashboards that use the dmarc_domains macro to use the correct argument <br /> **[ADD]** Added option in the overview dashboard to resolve the source ip, disabled by default <br />for perfomance and becauce the TA-dmarc has the option to resolve the ip's at ingestion time 
| 2018-06-26 | 3.2     | Arnold  | **[ADD]** Added spf_resolving_filter lookup to filter out known false positives from the SPF <br /> Resolving dashboard.
| 2018-09-21 | 3.2.1   | Arnold  | **[FIX]** Corrected typo in transforms.conf
| 2018-10-17 | 3.3.1   | Arnold  | **[ADD]** Added dashboard to help create the correct DNS entry's for DMARK and (advanced)<br /> SPF records.
| 2018-11-01 | 3.4.1   | Arnold  | **[MOD]** Changes to the DMARC and SPF help dashboard
| 2018-11-02 | 3.4.2   | Arnold  | **[FIX]** Corrected typo in the DMARC and SPF help dashboard <br /> **[ADD]** Added the new dashboard to the app menu
| 2018-11-05 | 3.4.3   | Arnold  | **[FIX]** Fixed a macro issue in the SPF Resolving dashboard
| 2019-03-11 | 3.5.1   | Arnold  | **[ADD]** Added the possiblity to use IPv6 ip addresses in the DMARC/SPF help dashboard, for the <br />advanced SPF options.<br /> **[ADD]** Added 2 IPv6 related macros, one to expand IPv6 addresses (add all the zero's back in) and <br />one to make the address suitable for dns records.
| 2019-03-25 | 3.6.1   | Arnold  | **[ADD]** Added field extracts, needed for version 3.5.1 of the TA-dmarc, due to script<br /> changes in that app
| 2019-04-11 | 3.6.2   | Arnold  | **[FIX]** Typo correction
| 2019-05-10 | 3.6.3   | Arnold  | **[FIX]** Typo in DMARC help dashboard
| 2019-05-28 | 3.6.4   | Arnold  | **[FIX]** wrong record for exists and redirect records in the DNS help dashboard
| 2019-07-11 | 3.7.0   | Arnold  | **[FIX]** typo in the DNS help dashboard regarding the exists vs redirect record.
| 2019-07-31 | 3.7.1   | Arnold  | **[ADD]** additional note on the SPF wildcard record in the "DMARC and SPF DNS help" dashboard
| 2019-09-12 | 3.7.2   | Arnold  | **[FIX]** in the auto_kv extraction the _KEY_1 and _VAL_1 were the wrong way around
| 2020-01-09 | 3.7.3   | Arnold  | **[FIX]** typo in the DNS help dashboard <br /> **[ADD]** new option in the DNS help dashboard if you don't send emails from subdomains.
| 2020-01-15 | 3.7.4   | Arnold  | **[DEL]** old dashboard dmarc-report
| 2020-08-25 | 3.7.5   | Arnold  | **[FIX]** fixed lookup problems with the dmarc_spf_check.py script.
| 2020-08-25 | 3.7.5   | Arnold  | **[FIX]** fixed csv writer problems in the dmarc_spf_check.py script.
| 2020-10-09 | 3.8.0   | Arnold  | **[FIX]** Somehow the DMARC/SPF help dashboard was overwriten with the DMARC overview one.
| 2021-04-14 | 3.8.1   | Arnold  | **[FIX]** Missing ";" behind the cross domain dmarc record in the DMARC help dashboard.
| 2021-05-06 | 4.0.1   | Arnold  | **[ADD]** Added the DKIM selector as a column in the overview dashboard (thanks [@jbouwh](https://github.com/jbouwh))<br /> **[FIX]** Made the script Splunk python3 compliant<br /> **[MOD]** Fixed a typo in a macro (thanks [@jbouwh](https://github.com/jbouwh))<br /> **[MOD]** Updated the Splunk SDK<br /> **[MOD]** Changed the DNS lookup to get rid of the nslookup dependency<br /> **[MOD]** Updated the custom classes to python3 

## dmarc_spf_check.py
| Date       | Version | Author  | **[Type]** Description                                                                |
|:-----------|:--------|:--------|:--------------------------------------------------------------------------------------|
| 2018-05-28 | 1.0     | Arnold  | **[NEW]** Initial version
| 2018-05-29 | 1.1     | Arnold  | **[ADD]** Added some logging
| 2018-05-30 | 1.2     | Arnold  | **[MOD]** Changed the dmarc_domain csv to be able to exclude domains from the spf lookup<br />domains with a exists: item in the spf record can't be resolved.    
| 2018-06-25 | 1.3     | Arnold  | **[DEL]** Disabled some super debug log
| 2020-08-25 | 1.4.0   | Arnold  | **[FIX]** Fixed a problem when there where multiple A records for a domain, only 1 was<br /> returned<br /> **[FIX]** Fixed single IP notation in the lookup, it is now written as a /32 to be able to do CIDR lookups<br /> **[ADD]** Added lookups for AAAA records. 
| 2020-08-26 | 1.5.0   | Arnold  | **[FIX]** Fixed a problem with writing back the record that didn't need checking in the<br /> spf_mailservers.csv
