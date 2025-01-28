#!/usr/bin/env python
#
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

import sys
from jhwhois.util.argparse import ArgumentParser
from jhwhois.whois.exceptions import WCException
from jhwhois.whois.whoisc import WhoisClient


def run():
    """
    Main entry point
    """
    try:
        args = ArgumentParser().run()
        if 'IANA WHOIS server' in args.host:
            print(args.host)
        else:
            wc = WhoisClient()
            ret = wc.lookup(args)
            print(ret)
        sys.exit(0)
    except WCException as e:
        print("{}: {}".format(type(e).__name__, str(e)))
        sys.exit(1)
