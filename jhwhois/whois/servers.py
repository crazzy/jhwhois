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
"""Contains all whois server references"""

WC_WHOIS_SERVERS = {
    'AFRINIC': {
        'hostname': 'whois.afrinic.net'
    },
    'APNIC': {
        'hostname': 'whois.apnic.net'
    },
    'ARIN': {
        'hostname': 'whois.arin.net'
    },
    'IANA': {
        'hostname': 'whois.iana.org'
    },
    'LACNIC': {
        'hostname': 'whois.lacnic.net'
    },
    'RIPE': {
        'hostname': 'whois.ripe.net'
    },
    'tld_se': {
        'hostname': 'whois.iis.se'
    },
    'ipv4': {
        'cidrs': {
            '169.254.0.0/16': 'whois.arin.net'
        }
    }
}

WC_WHOIS_BANNED_REFERRALS = [
]
