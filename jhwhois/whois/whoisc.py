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
import re
import socket
from jhwhois.whois.exceptions import WCConnectionFailedException
from jhwhois.whois.exceptions import WCDNSLookupFailedException
from jhwhois.whois.servers import WC_WHOIS_BANNED_REFERRALS

WC_SOCK_TIMEOUT = 10


class WhoisClient:
    def __init__(self):
        self.sock = None

    def lookup(self, args, recursion=[]):
        result = self.query(args.host, args.port, args.query)
        if args.type == 'domain':
            referral = self._parse_domain_referral(result)
            # TODO: Add a validate referral function
            if referral and referral not in recursion and referral not in WC_WHOIS_BANNED_REFERRALS:
                args2 = args
                args2.host = referral
                recursion.append(referral)
                result += "\n[Referral server {}]\n".format(referral)
                result += self.lookup(args2, recursion)
        if args.type == 'asn':
            referral = self._parse_asn_referral(result)
            if referral and referral not in recursion and referral not in WC_WHOIS_BANNED_REFERRALS:
                args2 = args
                args2.host = referral
                recursion.append(referral)
                result = "\n[Referral server {}]\n".format(referral)
                result += self.lookup(args2, recursion)
        return result

    def query(self, hostname, port, query):
        # Prepare query
        query = "{}\r\n".format(query).encode()

        # Resolve the hostname
        hostname, aliaslist, ipaddrlist = self._gethostbyname(hostname)

        # Get and check that we have a connection
        for ip in ipaddrlist:
            self._conn(ip, port)
            if self.sock:
                break
        if not self.sock:
            raise WCConnectionFailedException("Unable to connect to host {}".format(hostname))

        # Send query and get response
        self.sock.sendall(query)
        response = self._recv()
        self.sock.close()

        return self._decode(response)

    def _gethostbyname(self, hostname):
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(hostname)
        except socket.gaierror:
            raise WCDNSLookupFailedException("Unable to lookup host {}".format(hostname))
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
        for line in io.StringIO(data):
            if line.startswith('refer:'):
                return str(line.split()[-1])
        return None

    def _parse_domain_referral(self, data):
        for line in io.StringIO(data):
            if line.lstrip().startswith('Registrar WHOIS Server:'):
                referral = str(line.split()[-1])
                if re.match(r'^[a-z0-9]+://.*', referral):
                    return None
                else:
                    return referral
        return None

    def _parse_asn_referral(self, data):
        for line in io.StringIO(data):
            if line.lstrip().startswith('ReferralServer:'):
                return str(line.split()[-1]).replace('whois://', '')
        return None
