#!/usr/bin/env python3

import base64

string = "ABBHHPJGTFRLKVGhpcyBpcyB0aGUgc2VjcmV0OiBwaWNvQ1RGe1IzNERJTkdfTE9LZF8="

for i in range(len(string)):
    dec = base64.b64decode(string[i:])
    print(dec)
