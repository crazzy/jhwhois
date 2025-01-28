# SPDX-License-Identifier: MIT
#
# MIT License
#
# Copyright (c) 2024 Johan Hedberg
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import io
import ipaddress
import re
import socket

import pyunycode
import validators

from jhwhois.whois.exceptions import WCConnectionFailedException
from jhwhois.whois.exceptions import WCDNSLookupFailedException
from jhwhois.whois.asn_mapping import WC_ASN_MAPPING
from jhwhois.whois.servers import WC_WHOIS_BANNED_REFERRALS, WC_WHOIS_SERVERS

WC_SOCK_TIMEOUT = 10


class WhoisClient:
    """
    As class name suggest, this is a whois client
    """
    def __init__(self, args):
        self.sock = None
        self.args = args

    def lookup(self, args=None, recursion=None):
        """
        Whois lookups happens here
        """
        if not args:
            args = self.args
        if not args.host:
            self._guess_whois_server()
            args = self.args
        if not args.host and args.type == 'raw':
            self.args.host = self._get_iana_referral_server(args.query)
            args = self.args
        # IANA referral check indicates this is actually handled by IANA
        # so we fast exit on that one (example.com is an example of this)
        if 'IANA WHOIS server' in args.host:
            return args.host
        # Run whois query
        result = self.query(args.host, args.port, args.query)
        if not recursion:
            recursion = []
        if args.type == 'domain':
            referral = self._parse_domain_referral(result)
            # TODO: Add a validate referral function
            if referral and referral not in recursion and referral not in WC_WHOIS_BANNED_REFERRALS:
                args2 = args
                args2.host = referral
                recursion.append(referral)
                result += f"\n[Referral server {referral}]\n"
                result += self.lookup(args2, recursion)
        if args.type == 'asn':
            referral = self._parse_asn_referral(result)
            if referral and referral not in recursion and referral not in WC_WHOIS_BANNED_REFERRALS:
                args2 = args
                args2.host = referral
                recursion.append(referral)
                result = f"\n[Referral server {referral}]\n"
                result += self.lookup(args2, recursion)
        return result

    def query(self, hostname, port, query):
        """
        Support-function to actually do the
        whois query over the network
        """
        # Prepare query
        query = f"{query}\r\n".encode()

        # Resolve the hostname
        hostname, _, ipaddrlist = self._gethostbyname(hostname)

        # Get and check that we have a connection
        for ip in ipaddrlist:
            self._conn(ip, port)
            if self.sock:
                break
        if not self.sock:
            raise WCConnectionFailedException(f"Unable to connect to host {hostname}")

        # Send query and get response
        self.sock.sendall(query)
        response = self._recv()
        self.sock.close()

        return self._decode(response)

    def _gethostbyname(self, hostname):
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(hostname)
        except socket.gaierror as e:
            raise WCDNSLookupFailedException(f"Unable to lookup host {hostname}") from e
        return (hostname, aliaslist, ipaddrlist)

    def _conn(self, ip, port):
        try:
            socket.inet_aton(ip)
            af = socket.AF_INET
        except socket.error:
            af = socket.AF_INET6
        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.settimeout(WC_SOCK_TIMEOUT)
        try:
            self.sock.connect((ip, port))
        except (TimeoutError, InterruptedError, ConnectionRefusedError):
            self.sock.close()
            self.sock = None
            return False

    def _recv(self):
        chunks = []
        while True:
            chunk = self.sock.recv(2048)
            if chunk == b'':
                break
            chunks.append(chunk)
        return b''.join(chunks)

    def _decode(self, data):
        try:
            return data.decode('UTF-8')
        except UnicodeDecodeError:
            return data.decode('iso-8859-1')

    def parse_iana_referral(self, data):
        """
        Gets the referral entry from IANA whois result
        """
        for line in io.StringIO(data):
            if line.startswith('refer:'):
                return str(line.split()[-1])
        return None

    def _parse_domain_referral(self, data):
        """
        Gets ICANN-style referral entries
        """
        for line in io.StringIO(data):
            if line.lstrip().startswith('Registrar WHOIS Server:'):
                referral = str(line.split()[-1])
                if re.match(r'^[a-z0-9]+://.*', referral):
                    return None
                return referral
        return None

    def _parse_asn_referral(self, data):
        for line in io.StringIO(data):
            if line.lstrip().startswith('ReferralServer:'):
                return str(line.split()[-1]).replace('whois://', '')
        return None

    def _get_iana_referral_server(self, query):
        ret = self.query(
            WC_WHOIS_SERVERS['IANA']['hostname'],
            socket.getservbyname(
                'whois',
                'tcp'
            ),
            query
        )
        referral = self.parse_iana_referral(ret)
        if not referral:
            return ret
        return referral

    def _guess_by_asn(self, asn):
        for asrange, refhost in WC_ASN_MAPPING.items():
            if '-' not in asrange and (int(asrange) == int(asn)):
                self.args.host = refhost
                break
            if '-' in asrange:
                rangeparts = asrange.split('-')
                lpart = int(rangeparts[0])
                rpart = int(rangeparts[1])
                if (lpart <= int(asn)) and (int(asn) <= rpart):
                    self.args.host = refhost
                    break
        if not self.args.host:
            self.args.host = WC_WHOIS_SERVERS['IANA']['hostname']

    def _guess_whois_server(self):  # pylint: disable=too-many-branches
        """
        Here we take semi-educated guesses of where to query
        """
        if ' ' in self.args.query:
            self.args.type = 'raw'
            return

        # Detect IDN domain names
        try:
            self.args.query.encode('ascii')
        except UnicodeEncodeError:
            self.args.query = pyunycode.convert(self.args.query)

        asn_match = re.fullmatch(r'^[aA][sS]([0-9]+)$', self.args.query)
        if asn_match:
            self._guess_by_asn(asn_match.group(1))
            self.args.type = 'asn'
        elif validators.ipv4(self.args.query) or validators.ipv6(self.args.query):
            for cidr, srv in WC_WHOIS_SERVERS['ipv4']['cidrs'].items():
                if ipaddress.ip_address(self.args.query.split("/")[0]) in ipaddress.ip_network(cidr):
                    self.args.host = srv
            # 0.0.0.0/0 and 0.0.0.0/32 special cases
            if self.args.query in ['0.0.0.0', '0.0.0.0/32']:
                self.args.query = 'NET-0-0-0-0-2'
                self.args.host = WC_WHOIS_SERVERS['ARIN']['hostname']
            elif ipaddress.ip_address(self.args.query.split('/')[0]) in ipaddress.ip_network('224.0.0.0/3'):
                self.args.host = WC_WHOIS_SERVERS['ARIN']['hostname']
            elif ipaddress.ip_address(self.args.query.split('/')[0]) in ipaddress.ip_network('0.0.0.0/8'):
                self.args.query = 'NET-0-0-0-0-1'
                self.args.host = WC_WHOIS_SERVERS['ARIN']['hostname']
            if not self.args.host:
                # TODO: This is not guaranteed to work all the time, there's lots of
                # corner cases, like JP-NIC, BR-NIC etc...
                self.args.host = self._get_iana_referral_server(self.args.query)
            self.args.type = 'ip'
        elif validators.domain(self.args.query.lower()):
            self.args.query = self.args.query.lower()
            self.args.type = 'domain'
            tld = self.args.query.split(".")[-1]
            if f"tld_{tld}" in WC_WHOIS_SERVERS.keys():  # pylint: disable=consider-iterating-dictionary
                self.args.host = WC_WHOIS_SERVERS[f"tld_{tld}"]['hostname']
            else:
                self.args.host = self._get_iana_referral_server(self.args.query)
        elif 'RIPE' in self.args.query:  # Highly likely a RIPE DB resource
            self.args.host = WC_WHOIS_SERVERS['RIPE']['hostname']
            self.args.type = 'raw'
        else:
            self.args.type = 'raw'
