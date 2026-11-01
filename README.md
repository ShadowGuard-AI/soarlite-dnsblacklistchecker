# soarlite-DnsBlacklistChecker
A command-line tool that checks a given domain or IP address against multiple DNS blacklists (DNSBLs) in parallel and reports the results, allowing for rapid identification of potentially malicious hosts. - Focused on Provides a simplified framework for automating repetitive security tasks, such as log analysis, incident response workflows, and security policy enforcement. Focuses on small, self-contained automation scripts driven by scheduled tasks.

## Install
`git clone https://github.com/ShadowGuardAI/soarlite-dnsblacklistchecker`

## Usage
`./soarlite-dnsblacklistchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-l`: No description provided
- `-v`: No description provided

## Behaviour notes

Checks use the async dnspython resolver (`dns.asyncresolver`, from the `dnspython` package). The result header prints the IP or domain exactly as given; the reversed IP form is the query form and appears only in verbose logs. The run prints a summary count of listed, not listed, and unknown results, and exits with status 1 when no server produced a definitive answer. Domains are validated label by label, and IP octets with leading zeros are rejected.

## License
Copyright (c) ShadowGuardAI
