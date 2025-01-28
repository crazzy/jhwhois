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
"""Argument parser for the whois client"""

import argparse
import socket
import sys
from jhwhois import __version__


class ArgumentParser():
    """
    As class name suggest, this is the argument parser
    """
    def __init__(self):
        self.args = None
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
            version=f'%(prog)s {__version__}'
        )
        self.parser.add_argument(
            'query',
            nargs="*"
        )

    def run(self):
        """Runs argument parsing"""
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
        if not hasattr(self.args, 'type'):
            self.args.type = 'raw'
        return self.args

    def show_help(self):
        """Helper function to trigger the help printing"""
        self.parser.print_help()
