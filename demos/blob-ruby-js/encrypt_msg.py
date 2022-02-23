#!/usr/bin/env python3

import pysodium, binascii

export_key = binascii.unhexlify('ed23adbfc61c9462ee501bee51c9ba75e21915b550b00eb1f5babde5f251dea91897d87200e73013b92a81d74e2a951d9fe017ada17af570c537ef7b061f38c2')
msg = b"OPAQUE is versatile, it can auth, protect at-rest and in-flight!"

res = b''.join(bytes([x^y]) for x,y in zip(export_key, msg))
print(res.hex())
