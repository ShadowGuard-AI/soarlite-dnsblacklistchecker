#!/usr/bin/env python3

import argparse
import asyncio
import dns.asyncresolver
import dns.exception
import dns.resolver
import logging
import re
import sys
import concurrent.futures  # For parallel execution
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# List of DNSBL servers (feel free to expand this list)
DNSBL_SERVERS = [
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "zen.spamhaus.org",
    "spam.abuse.ch",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
]


async def check_dnsbl(target, dnsbl_server, resolver):
    """
    Asynchronously checks a target (domain or IP) against a single DNSBL server.

    Args:
        target (str): The target domain or IP address to check.
        dnsbl_server (str): The DNSBL server to query.
        resolver (dns.asyncresolver.Resolver):  A pre-configured async DNS resolver object.

    Returns:
        tuple: A tuple containing the DNSBL server and a boolean indicating if the target is listed.
               Returns (dnsbl_server, None) on DNS resolution failure.
    """
    try:
        # Construct the query string
        # The query is plain string joining, so the reversal for an IP has to happen before this point, in main. Pass a domain and an IP through the same path and they are treated identically here, which is why the two argument branches in main diverge before they converge.
        query = target + "." + dnsbl_server
        # Perform the DNS query
        answers = await resolver.resolve(query, "A")  # Await the result

        if answers:
            logging.debug(f"Target {target} listed on {dnsbl_server}")
            return dnsbl_server, True
        else:
            logging.debug(f"Target {target} not listed on {dnsbl_server}")
            return dnsbl_server, False
    # For a blacklist, no such name is the good answer, not an error. I map it to False rather than None because the server did answer, and reserving None for cases where nothing was learned keeps the summary honest.
    except dns.resolver.NXDOMAIN:
        logging.debug(f"Target {target} not listed on {dnsbl_server} (NXDOMAIN)")
        return dnsbl_server, False  # Not listed
    except dns.resolver.NoAnswer:
        logging.debug(f"Target {target} not listed on {dnsbl_server} (NoAnswer)")
        return dnsbl_server, False  # Not listed
    except dns.exception.Timeout:
        logging.warning(f"Timeout querying {dnsbl_server} for {target}")
        return dnsbl_server, None  # Timeout
    except dns.resolver.YxDomain:
        logging.warning(f"YXDOMAIN error querying {dnsbl_server} for {target}")
        return dnsbl_server, None
    except Exception as e:
        logging.error(
            f"Error querying {dnsbl_server} for {target}: {e}", exc_info=True
        )
        return dnsbl_server, None  # Error


async def check_target_parallel(target, dnsbl_servers):
    """
    Checks a target against multiple DNSBL servers in parallel using asyncio.

    Args:
        target (str): The target domain or IP address to check.
        dnsbl_servers (list): A list of DNSBL server addresses.

    Returns:
        dict: A dictionary where keys are DNSBL servers and values are booleans
              indicating if the target is listed (True), not listed (False), or
              the query resulted in an error (None).
    """
    results = {}
    resolver = dns.asyncresolver.Resolver()  # Create an async resolver instance
    resolver.timeout = 5  # Set timeout to 5 seconds
    # One resolver is shared by every check in the batch. A slow server does not get its own budget, and a resolver setting changed for one query would change them all, so the timeout is set once here and left alone.

    # Use asyncio.gather to run the checks concurrently
    tasks = [check_dnsbl(target, server, resolver) for server in dnsbl_servers]
    completed = await asyncio.gather(*tasks)

    for server, listed in completed:
        results[server] = listed

    return results


def is_valid_domain(domain):
    """
    Validates if a given string is a valid domain name.

    Args:
        domain (str): The string to validate.

    Returns:
        bool: True if the string is a valid domain, False otherwise.
    """
    try:
        if "." not in domain or len(domain) > 253:
            return False
        domain.encode("idna")  # Check for IDNA compatibility
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        # An all numeric name is rejected as a domain even though the label rules below would pass it. That keeps a malformed IP like 999.1.2.3 from being checked as a domain name and queried in the wrong form.
        if all(label.isdigit() for label in labels):
            return False
        for label in labels:
            if not 1 <= len(label) <= 63:
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
            if not re.fullmatch(r'[A-Za-z0-9-]+', label):
                return False
        return True
    except UnicodeError:
        return False


def is_valid_ip(ip):
    """
    Validates if a given string is a valid IPv4 address.

    Args:
        ip (str): The string to validate.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or part == "":
                return False
            # Leading zeroes are refused rather than cleaned up. Different resolvers read 010 as ten or as octal eight, and I would rather reject the input than guess which address the caller meant.
            if len(part) > 1 and part.startswith("0"):
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except ValueError:
        return False


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Check a domain or IP address against multiple DNS blacklists."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d", "--domain", help="The domain name to check (e.g., example.com)"
    )
    group.add_argument("-i", "--ip", help="The IP address to check (e.g., 127.0.0.1)")
    parser.add_argument(
        "-l",
        "--list",
        nargs="+",
        default=DNSBL_SERVERS,
        help=f"A list of DNSBL servers to check against. Defaults to: {DNSBL_SERVERS}",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level)."
    )

    return parser


def main():
    """
    The main function of the script.  Parses arguments, validates inputs, performs DNSBL checks,
    and prints the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    original_target = None
    target = None
    if args.domain:
        if not is_valid_domain(args.domain):
            logging.error("Invalid domain name provided.")
            sys.exit(1)
        original_target = args.domain
        target = args.domain
    elif args.ip:
        if not is_valid_ip(args.ip):
            logging.error("Invalid IP address provided.")
            sys.exit(1)
        original_target = args.ip
        # Reverse the IP address for DNSBL queries. The reversed form is
        # the query form only and appears only in verbose logs.
        parts = args.ip.split(".")
        # Only the IP form is reversed. The domain form goes in as written, because domain based lists expect the name itself, and reversing a domain would query a name nobody published an answer for.
        target = ".".join(reversed(parts))
        if args.verbose:
            logging.debug(f"Reversed query form for {original_target}: {target}")

    dnsbl_servers = args.list

    try:
        # Run the checks asynchronously
        results = asyncio.run(check_target_parallel(target, dnsbl_servers))

        print(f"DNSBL check results for: {original_target}")
        listed_count = 0
        not_listed_count = 0
        unknown_count = 0
        for server, listed in results.items():
            if listed is True:
                listed_count += 1
                print(f"  {server}: LISTED")
            elif listed is False:
                not_listed_count += 1
                print(f"  {server}: NOT LISTED")
            else:
                unknown_count += 1
                print(f"  {server}: UNKNOWN (Error or Timeout)")
        print(f"Summary: {listed_count} listed, {not_listed_count} not listed, {unknown_count} unknown.")
        # If every server came back unknown, the printed summary alone would look like a completed check. This exit is what separates a run that learned nothing from a run that learned the target is clean everywhere.
        if listed_count + not_listed_count == 0:
            logging.error("No DNSBL server produced a definitive answer.")
            sys.exit(1)

    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()


# Usage Examples:
#
# 1. Check a domain against the default DNSBL servers:
#    python dnsbl_checker.py -d example.com
#
# 2. Check an IP address against the default DNSBL servers:
#    python dnsbl_checker.py -i 127.0.0.1
#
# 3. Check a domain against a specific list of DNSBL servers:
#    python dnsbl_checker.py -d example.com -l bl.spamcop.net zen.spamhaus.org
#
# 4. Check an IP address with verbose logging:
#    python dnsbl_checker.py -i 127.0.0.1 -v
#
# 5. Check a domain with a custom list of DNSBLs and verbose logging
#    python dnsbl_checker.py -d example.com -l bl.spamcop.net dnsbl.sorbs.net -v
