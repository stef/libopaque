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

from mitmproxy.http import Headers
import requests, sys, binascii, sasl, subprocess

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

class SASL:
    def  response(self, flow):
        if flow.response.status_code != 401:
            #print(f'"{url}" did not return 401')
            return
        www_auth = flow.response.headers["www-authenticate"]
        #print(f"www-authenticate: {www_auth}")
        if not www_auth.startswith("SASL "):
            #print("bad auth method in 2nd step of opaque sasl auth")
            return

        fields = dict((x.strip() for x in kv.split('=')) for kv in www_auth[5:].split(','))

        if 'realm' not in fields or 'mech' not in fields:
            #print("bad parameters in sasl auth header")
            return

        client = sasl.Client()
        user, pwd = getpwd(fields['realm'])
        client.setAttr("username", user)
        client.setAttr("password", pwd)
        client.init()
        ret, mech, response = client.start('OPAQUE')
        if not ret:
            raise Exception(client.getError())

        c2s = binascii.b2a_base64(response, newline=False).decode('utf8')
        h = {"Authorization": f'SASL c2s="{c2s}",realm={fields["realm"]},mech="OPAQUE"'}
        #print("headers", h)
        #print("url", flow.request.url)
        while True:
            r = requests.get(flow.request.url, headers=h)

            #print("response status:", r.status_code)
            if r.status_code != 401:
                break

            www_auth = r.headers.get("WWW-Authenticate")
            #print(f"www-authenticate: {www_auth}")
            if not www_auth.startswith("SASL "):
                #print("bad auth method in 2nd step of opaque sasl auth")
                break

            fields = dict((x.strip() for x in kv.split('=')) for kv in www_auth[5:].split(','))
            s2c = binascii.a2b_base64(fields['s2c'])
            s2s = fields['s2s']

            ret, response = client.step(s2c)
            if not ret:
                raise Exception(client.getError())

            c2s = binascii.b2a_base64(response, newline=False).decode('utf8')
            h = {"Authorization": f'SASL c2s="{c2s}",s2s={fields["s2s"]}'}

        #print(r.text)
        flow.response.headers = Headers(**{str(k): str(v) for k, v in r.headers.items()})
        flow.response.status_code = r.status_code
        flow.response.reason = r.reason
        flow.response.raw_content = r.content

addons = [
    SASL()
]
