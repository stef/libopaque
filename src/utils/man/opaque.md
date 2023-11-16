% opaque(1) | simple command-line frontend for libopaque

# NAME

opaque - simple command-line frontend for libopaque

# SYNOPSIS

Create new OPAQUE records

Create new opaque record - offline
```
echo -n password | opaque init idU idS 3>export_key [4<skS] >record
```

Initiate new online registration
```
echo -n password | opaque register >msg 3>ctx
```

Respond to new online registration request
```
opaque respond <msg >rpub 3>rsec [4<skS]
```

Finalize online registration
```
opaque finalize idU idS <ctx 4<rpub 3>export_key >record
```

Complete online record
```
opaque store <rec 3<rsec >record
```

Server portion of online registration
```
socat | opaque server-reg 3>record [4<skS]
```

User portion of online registration
```
socat | opaque user-reg idU idS 3< <(echo -n password) 4>export_key
```

Run OPAQUE

Server portion of OPAQUE session
```
socat | opaque server idU idS context 3<record 4>shared_key
```

User portion of OPAQUE session
```
socat | opaque user idU idS context 3< <(echo -n password) 4>export_key 5>shared_key [6<pkS]
```

# DESCRIPTION

The OPAQUE protocol is an asymmetric password-authenticated key-exchange.
Essentially it allows a client to establish a shared secret with a server based
on only having a password. The client doesn't need to store any state. The
protocol has two phases:

  - In the initialization phase a client registers with the server.
  - In the AKE phase the client and server establish a shared secret.

The initialization only needs to be executed once, the key-exchange can be
executed as many times as necessary.

## Initialization

Initializing OPAQUE (registration) can be done either online or offline. The
online variant has the benefit that the server never learns anything about the
users password, with the drawback that this requires 3 messages to be exchanged
by the client and the server.

The offline initialization is much easier, however either the user learns the
servers secret, or the server learns the users password. The latter might be
useful if some organisation wants to enforce some password quality rules and
check those upon registration. The drawback is that either way, some sensitive
information leaks to the other party.

### Offline Registration

```
echo -n password | ./opaque init user server >record 3>export_key
```

### Online Registration
#### socat style
On the server:
```
socat tcp-l:23523,reuseaddr,fork system:"bash -c \'opaque server-reg user server 3>record\'"
```
On the client:
```
socat tcp:127.0.0.1:23523 exec:'bash -c \"opaque user-reg user server 3< <(echo -n password) 4>export_key\"'
```
#### tcpserver style
On the server:
```
s6-tcpserver 127.0.0.1 23523 bash -c 'opaque server-reg user server 3>record'
```
On the client:
```
s6-tcpclient 127.0.0.1 23523 bash -c "opaque user-reg user server <&6 >&7 3< <(echo -n password) 4>export_key"
```
#### Manually
It's possible to do all 4 steps seperately, in case you cannot connect to the server directly, then:

The user initiates with:
```
echo -n password | opaque register >msg 3>ctx
```

The server gets `msg` and responds with rpub, while keeping rsec secret:
```
cat msg | opaque respond >rpub 3>rsec
```

The user receives `rpub` and creates stub record and optionally uses the export key to encrypt more data:
```
cat ctx | opaque finalize user server 4<rpub >record 3>export_key
```

the server finalizes the record by completing the stub record from the client:
```
cat rec | opaque store user server >record 3<rsec
```

## Running OPAQUE
### tcpserver style
On the server:
```
s6-tcpserver 127.0.0.1 23523 bash -c './opaque server user server context 3<record 4>shared_secret'
```
On the client:
```
s6-tcpclient 127.0.0.1 23523 bash -c "./opaque user user server context <&6 >&7 3< <(echo -n password) 4>export_key 5>shared_secret"
```
### socat style
On the server:
```
socat tcp-l:23523,reuseaddr,fork system:"bash -c \'./opaque server user server context 3<record 4>shared_secret\'"
```
On the client:
```
socat tcp:127.0.0.1:23523 exec:'bash -c \"./opaque user user server context 3< <(echo -n password) 4>export_key  5>shared_secret\"'
```

# REPORTING BUGS

https://github.com/stef/libopaque/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License LGPLv3+: GNU Lesser GPL version 3 or later <https://gnu.org/licenses/lgpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

https://ctrlc.hu/~stef/blog/tags/opaque/

`socat(1)`, `tcpserver(1)`
