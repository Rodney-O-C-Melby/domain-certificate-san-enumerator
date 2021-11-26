#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Domain SSL Certificate SAN Enumerator - Returns the given domains subdomains using Subject Alternate Names (SAN).

    GNU LGPL v3
    Copyright (C) 2021 Rodney Olav Christopher Melby

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

# Imports
from argparse import ArgumentParser
from os import geteuid
from re import match
from socket import gaierror
from ssl import get_server_certificate
from sys import argv
from sys import exit
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import DNSName
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.x509.extensions import SubjectAlternativeName  # for certificate SAN grabbing
from scapy.layers.dns import DNS, DNSQR  # for DNS queries
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
from scapy.volatile import RandShort
# from cryptography.x509.oid import ExtensionOID

__author__ = "Rodney Olav Christopher Melby"
__copyright__ = "Copyright 2022, Rodney Olav Christopher Melby"
__credits__ = ["Rodney Olav Christopher Melby"]
__license__ = "LGPL v3"
__version__ = "1.0.1"
__maintainer__ = "Rodney Olav Christopher Melby"
__status__ = "Production"

""" Written on Python v3.9.1 for NIX/UNIX/LINUX systems, should run on python 3.6 - 3.9, not tested. """


class Colours:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def get_local_name_server():
    """ Returns the local machines nameserver IP or cloud fare dns. """
    nameserver = "1.1.1.1"
    with open("/etc/resolv.conf") as fh:
        for line in fh.readlines():
            groups = match("nameserver (.*)", line)
            if groups:
                nameserver = groups.groups()[0]
                break
    return nameserver


def query_address(hostname, nameserver):
    """ Returns the A record of a live domain name else none. """
    dns_request = IP(dst=nameserver) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=hostname, qtype="A",
                                                                                             qclass="IN"))
    response = sr1(dns_request, verbose=0)  # scapy python library
    ips = []
    # print(response.show())  # for debugging
    if response[DNS].rcode == 0:  # response good
        for count in range(response[DNS].ancount):
            ips.append(response[DNS].an[count].rdata)
            # print("response ", response[DNS].an[count].rdata)
        return ips
    if response[DNS].rcode == 3:  # name error
        print("Error[DOMAIN]:", hostname, " name or service unknown. Check domain name!")
        exit()
    else:
        print("Error Response code:", response[DNS].rcode)
        exit()


def query_common_address(hostname, nameserver):
    """ Returns the A record of a live domain name else none. """
    dns_request = IP(dst=nameserver) / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=DNSQR(qname=hostname, qtype="A",
                                                                                             qclass="IN"))
    response = sr1(dns_request, verbose=0)  # scapy python library
    ips = []
    if response is None:  # name error (different from above)
        return 1
    if response[DNS].rcode == 0:  # response good
        for count in range(response[DNS].ancount):
            ips.append(response[DNS].an[count].rdata)
        return ips
    if response[DNS].rcode == 3:  # name error
        return 1
    else:
        print("Response code:", response[DNS].rcode)
        return


def query_soa(hostname, nameserver):
    """ Returns the SOA record of a live domain name else none. """
    try:
        dns_request = IP(dst=nameserver)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,
                                                                              qd=DNSQR(qname=hostname, qtype="SOA"))
        response = sr1(dns_request, verbose=0)  # scapy python library
        if response[DNS].rcode == 0:  # response good
            if response[DNS].ancount > 0:
                return response.an[0].mname.decode("utf-8")
        if response[DNS].rcode == 3:  # name error
            return 1
        else:
            print("Response code:", response[DNS].rcode)
            return None
    except gaierror:
        # print("Error[SOA]:", hostname, " name or service unknown. Check domain name!")
        return 1


def query_nameserver(hostname, nameserver):
    """ Returns a list of nameservers from a live domain name else none. """
    dns_request = IP(dst=nameserver)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=hostname, qtype="NS"))
    response = sr1(dns_request, verbose=0)  # scapy python library
    ns = []
    if response[DNS].rcode == 0:  # response good
        ns.append(response.an[0].rdata.decode("utf-8"))
        ns.append(response.an[1].rdata.decode("utf-8"))
        return ns
    if response[DNS].rcode == 3:  # name error
        return 1
    else:
        print("Response code:", response[DNS].rcode)
        return


def query_common_name(hostname, port=443):
    """ Returns the common name for a domain from the domains ssl certificate. """
    try:
        names = []
        certificate: bytes = get_server_certificate((hostname, port)).encode('utf-8')
        loaded_cert = load_pem_x509_certificate(certificate, default_backend())
        common_name = loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if "*" in common_name[0].value[0]:  # handle * wildcard domains for ip lookup
            wildcard_test = common_name[0].value[2:]
        else:
            wildcard_test = common_name[0].value
        # print(wildcard_test)
        for value in wildcard_test:  # appends values to common names list
            names.append(value)
        return wildcard_test
    except gaierror:
        return 1


def query_san(hostname, port=443):
    """ Returns a list of subdomains from the domains ssl certificate SAN. """
    try:
        certificate: bytes = get_server_certificate((hostname, port)).encode('utf-8')
        loaded_cert = load_pem_x509_certificate(certificate, default_backend())
        san = loaded_cert.extensions.get_extension_for_class(SubjectAlternativeName)  # cryptography < v1.0
        # TODO: maybe library change from cryptography, import commented above
        # san = loaded_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)# cryptography > v1.0
        sans = san.value.get_values_for_type(DNSName)
        return sans
    except gaierror:
        return 1


def print_list_as_string(data):
    """ Print a list of domains and IP addresses. """
    string = ""
    for value in data:
        try:
            string += " " + value
        except TypeError:
            string += "Root " + value.decode("utf-8") + " ->"
    return string


def handle_permissions():
    """ Require root permissions to run program. """
    if not geteuid() == 0:  # check root permissions
        exit("\nOnly root can run this script. Try using sudo!\n")


def handle_arguments():
    """ Ensure root permissions and Return parser containing help and usage. """
    handle_permissions()
    parser = ArgumentParser(description="Domain SSL Certificate SAN Enumerator dcse returns the given domains "
                                        "subdomains using SAN.")
    parser.add_argument("FQDN", help="The target domain name.")
    parser.add_argument("-v", "--version", action="version", version='%(prog)s version 1.0.0')
    parser.add_argument("-n", "--nameserver", action="store", help="The nameserver to use for target lookups")
    return parser.parse_args()


def dcse(hostname, nameserver):
    """ Checks a domains SSL certificate for SANs (subdomains) and prints domain DNS data. """
    # Query DNS records
    ip_list = query_address(hostname, nameserver)  # get A record
    soa = query_soa(hostname, nameserver)  # get SOA record
    soa_ip_list = query_address(soa, nameserver)  # get SOA A record
    ns_list = query_nameserver(hostname, nameserver)  # get SOA A record
    # Query SSL Certificates
    common_name_list = query_common_name(hostname)  # get domain common name
    san_list = query_san(hostname)  # get SSL cert SAN list

    # handle errors
    if ip_list == 1:
        print("Error[DOMAIN]:", hostname, " name or service unknown. Check domain name!")
    else:  # pretty print results
        for ip in ip_list:  # pretty print domain and ip
            print(f"{Colours.BLUE}{Colours.BOLD} DOMAIN NAME:{Colours.END}{Colours.FAIL}{Colours.BOLD}", hostname,
                  f"{Colours.END}{Colours.GREEN}{Colours.BOLD}", ip, f"{Colours.END}")
        for soa_ip in soa_ip_list:
            print(f"{Colours.BLUE}{Colours.BOLD} DOMAIN SOA:{Colours.END}", f"{Colours.FAIL}{Colours.BOLD}", soa,
                  f"{Colours.END}", f"{Colours.GREEN}{Colours.BOLD}", soa_ip, f"{Colours.END}")
        for ns in ns_list:
            print(f"{Colours.BLUE}{Colours.BOLD} DOMAIN NS:{Colours.END}", f"{Colours.FAIL}{Colours.BOLD}", ns,
                  f"{Colours.END}", f"{Colours.GREEN}{Colours.BOLD}",
                  print_list_as_string(query_address(ns, nameserver)), f"{Colours.END}")

        print(f"{Colours.BLUE}{Colours.BOLD} DOMAIN COMMON NAME:{Colours.END}", f"{Colours.FAIL}{Colours.BOLD}",
              common_name_list, f"{Colours.END}", f"{Colours.GREEN}{Colours.BOLD}",
              print_list_as_string(query_address(common_name_list, nameserver)), f"{Colours.END}")
        for san in san_list:
            print(f"{Colours.BLUE}{Colours.BOLD} Subdomain:{Colours.END}", f"{Colours.GREEN}{Colours.BOLD}", san,
                  f"{Colours.END}")


def main():
    """ Main program - handle user input, usage etc """
    server = get_local_name_server()
    arguments = handle_arguments()  # handle optional arguments help and usage

    # handle cmd line arguments
    if len(argv) == 1:
        dcse("zonetransfer.me", server)  # call dcse with given domain
        exit(0)  # exit to avoid arguments error
    if arguments.FQDN and not arguments.nameserver:
        domain = argv[1]  # get domain
        dcse(domain, server)  # call dcse with given domain
    if arguments.FQDN and arguments.nameserver:
        domain = argv[3]  # get domain
        nameserver = argv[2]  # get nameserver
        print("Using Nameserver:", nameserver)
        dcse(domain, server)  # call dcse with given domain


if __name__ == '__main__':
    main()  # run main
