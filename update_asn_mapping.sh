#!/usr/bin/env bash
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

fetch_csv() {
	curl -Ss https://www.iana.org/assignments/as-numbers/as-numbers-1.csv
	curl -Ss https://www.iana.org/assignments/as-numbers/as-numbers-2.csv
}

filter_csv() {
	grep -E '^[0-9].*(AFRINIC|APNIC|ARIN|LACNIC|RIPE)' | awk -F, '{print $1","$3}'
}

{
echo "# comment
WC_ASN_MAPPING = {"

fetch_csv | filter_csv | while read -r line; do
	range=$(echo "$line" | awk -F, '{print $1;}')
	target=$(echo "$line" | awk -F, '{print $2;}')
	echo "    '${range}': '${target}',"
done
echo "}"
} > jhwhois/whois/asn_mapping.py
