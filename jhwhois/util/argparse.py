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

import argparse
import pyunycode
import re
import socket
import sys
import validators
from jhwhois import __version__
from jhwhois.whois.asn_mapping import WC_ASN_MAPPING
from jhwhois.whois.exceptions import WCReferralNotFoundException
from jhwhois.whois.servers import WC_WHOIS_SERVERS
from jhwhois.whois.whoisc import WhoisClient


class ArgumentParser():
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            add_help=False,
            description='jhwhois - Modern whois client',
            prog='jhwhois',
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30)
        )
        self.parser.add_argument(
            '-H', '--help',
            required=False,
            help="Show help text",
            action='store_true'
        )
        self.parser.add_argument(
            '-h', '--host',
            metavar='<host>',
            required=False,
            help='Whois server hostname'
        )
        self.parser.add_argument(
            '-p', '--port',
            metavar='<port>',
            required=False,
            help='Whois server port',
            type=int
        )
        self.parser.add_argument(
            '-v', '--version',
            help="Show program's version number",
            action='version',
            version='%(prog)s {}'.format(__version__)
        )
        self.parser.add_argument(
            'query',
            nargs="*"
        )

    def run(self):
        # Parse args and check for eventual issues
        self.args = self.parser.parse_args()
        if self.args.help:
            self.show_help()
            sys.exit(0)
        elif not self.args.query or (0 == len(self.args.query)):
            self.show_help()
            sys.exit(0)
        self.args.query = " ".join(self.args.query)
        if not self.args.port:
            self.args.port = socket.getservbyname('whois', 'tcp')
        if not self.args.host:
            self._guess_whois_server()
        if not self.args.host and self.args.type == 'raw':
            self.args.host = self._get_iana_referral_server(self.args.query)
        if not hasattr(self.args, 'type'):
            self.args.type = 'raw'
        return self.args

    def show_help(self):
        self.parser.print_help()

    def _guess_whois_server(self):
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
            # TODO: This is not guaranteed to work all the time, there's lots of
            # corner cases, like JP-NIC, BR-NIC etc...
            self.args.host = self._get_iana_referral_server(self.args.query)
            self.args.type = 'ip'
        elif validators.domain(self.args.query.lower()):
            self.args.query = self.args.query.lower()
            self.args.type = 'domain'
            tld = self.args.query.split(".")[-1]
            if "tld_{}".format(tld) in WC_WHOIS_SERVERS.keys():
                self.args.host = WC_WHOIS_SERVERS['tld_{}'.format(tld)]['hostname']
            else:
                self.args.host = self._get_iana_referral_server(self.args.query)
        elif 'RIPE' in self.args.query:  # Highly likely a RIPE DB resource
            self.args.host = WC_WHOIS_SERVERS['RIPE']['hostname']
            self.args.type = 'raw'
        else:
            self.args.type = 'raw'

    def _guess_by_asn(self, asn):
        for asrange, refhost in WC_ASN_MAPPING.items():
            if '-' not in asrange and (int(asrange) == int(asn)):
                self.args.host = refhost
                break
            elif '-' in asrange:
                rangeparts = asrange.split('-')
                lpart = int(rangeparts[0])
                rpart = int(rangeparts[1])
                if (lpart <= int(asn)) and (int(asn) <= rpart):
                    self.args.host = refhost
                    break
        if not self.args.host:
            self.args.host = WC_WHOIS_SERVERS['IANA']['hostname']

    def _get_iana_referral_server(self, query):
        wc = WhoisClient()
        ret = wc.query(WC_WHOIS_SERVERS['IANA']['hostname'], socket.getservbyname('whois', 'tcp'), query)
        referral = wc.parse_iana_referral(ret)
        if not referral:
            raise WCReferralNotFoundException("Can't find IANA referral for {}".format(query))
        else:
            return referral
