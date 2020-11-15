#!/usr/bin/python3

from itertools import product

# skU : 02
# pkU : 012
# pkS : 12
# idU : 012
# idS : 012

#print('\n'.join("{:>08b} {}".format(sum(int(b)<<(i*2) for i,b in enumerate(c) ), c) for c in product('012','12','012','012')))
print('\n'.join('"\\x{:>02x}\\x{:>02x}",'.format(sum(int(b)<<(i*2) for i,b in enumerate(c) ) & 0xff ,
                                                 sum(int(b)<<(i*2) for i,b in enumerate(c) ) >> 8 
                                                ) for c in product('01', '012','12','012','012')))
