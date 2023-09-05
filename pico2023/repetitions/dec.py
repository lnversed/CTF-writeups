#!/usr/bin/env python3

import base64

dec = ""

with open("./enc_flag") as f:
    for i in f.readlines():
        enc_string = i.strip("\n")
        dec += enc_string.strip("\n")
       
dec = base64.b64decode(dec)
print(dec)

            
