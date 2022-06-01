#!/usr/bin/env python3
#
# This file is part of libopaque.
#
# SPDX-FileCopyrightText:  2022, Marsiske Stefan <opaque@ctrlc.hu>
# SPDX-License-Identifier:  GPL-3.0-or-later
#
# libopaque is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 3 of the License, or
# (at your option) any later version.
#
# libopaque is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 3 for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, If not, see <http://www.gnu.org/licenses/>.

import subprocess, sasl, struct, json, binascii

log = '/tmp/a'

def getpwd(realm):
    args = f'--forms --add-entry="User name" --add-password=Password --text="{realm}"'.split(' ')
    proc=subprocess.Popen(['/usr/bin/zenity', *args],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise
    ptr = out.find(b'|')
    if ptr == -1: raise
    return out[:ptr].decode('utf8'), out[ptr+1:-1].decode('utf8')

# Send message using Native messaging protocol
def send_message(data):
  msg = json.dumps(data).encode('utf-8')
  if log:
    log.write(msg)
    log.write(b'\n')
    log.flush()
  length = struct.pack('@I', len(msg))
  sys.stdout.buffer.write(length)
  sys.stdout.buffer.write(msg)
  sys.stdout.buffer.flush()

def main():
  global log
  if log: log = open(log,'ab')
  clients = {}
  while True:
    # Read message using Native messaging protocol
    length_bytes = sys.stdin.buffer.read(4)
    if len(length_bytes) == 0:
      return

    length = struct.unpack('i', length_bytes)[0]
    data = json.loads(sys.stdin.buffer.read(length).decode('utf-8'))

    if log:
      log.write(repr(data).encode())
      log.write(b'\n')
      log.flush()

    res = {"s2s": data.get("s2s",""),
           "mech": data.get("mech",""),
           "requestId": data.get("requestId",""),
           "extraInfoSpec": data.get("extraInfoSpec","")}

    if data.get("mech"):
        client = sasl.Client()
        user, pwd = getpwd(data['realm'])
        client.setAttr("username", user)
        client.setAttr("password", pwd)
        log.write(f'user: "{user}", password: "{pwd}\n"'.encode())
        client.init()
        ret, mech, response = client.start('OPAQUE')
        if not ret:
            send_message({ 'error': client.getError().decode('utf8')})
            raise Exception(client.getError())
        res['c2s'] = binascii.b2a_base64(response, newline=False).decode('utf8')
        clients[data['requestId']]=client
    elif data['requestId'] in clients:
        client = clients[data['requestId']]
        s2c = binascii.a2b_base64(data['s2c'])
        if s2c:
            ret, response = client.step(s2c)
            if not ret:
                send_message({ 'error': client.getError().decode('utf8')})
                raise Exception(client.getError())
            res['c2s'] = binascii.b2a_base64(response, newline=False).decode('utf8')
    else:
        send_message({ 'results': 'fail' })
        raise
    send_message(res)

if __name__ == '__main__':
  main()
