#!/usr/bin/env python

import json
from itertools import zip_longest # for Python 3.x

def split_by_n(iterable, n):
    return zip_longest(*[iter(iterable)]*n, fillvalue='')

# src: https://github.com/cfrg/draft-irtf-cfrg-opaque/blob/c8f858d015836ea555543611fa845fe128264653/poc/vectors/vectors.json
vectors = """
{
"config": {
      "Context": "4f50415155452d504f43",
      "Fake": "False",
      "Group": "ristretto255",
      "Hash": "SHA512",
      "KDF": "HKDF-SHA512",
      "KSF": "Identity",
      "MAC": "HMAC-SHA512",
      "Name": "3DH",
      "Nh": "64",
      "Nm": "64",
      "Nok": "32",
      "Npk": "32",
      "Nsk": "32",
      "Nx": "64",
      "OPRF": "ristretto255-SHA512"
    },
    "inputs": {
      "blind_login": "6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308",
      "blind_registration": "76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01",
      "client_keyshare_seed": "82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b",
      "client_nonce": "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc",
      "credential_identifier": "31323334",
      "envelope_nonce": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec",
      "masking_nonce": "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
      "oprf_seed": "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef",
      "password": "436f7272656374486f72736542617474657279537461706c65",
      "server_keyshare_seed": "05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f",
      "server_nonce": "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
      "server_private_key": "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d",
      "server_public_key": "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"
    },
    "intermediates": {
      "auth_key": "6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494fc555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822",
      "client_mac_key": "91750adbac54a5e8e53b4c233cc8d369fe83b0de1b6a3cd85575eeb0bb01a6a90a086a2cf5fe75fff2a9379c30ba9049510a33b5b0b1444a88800fc3eee2260d",
      "client_public_key": "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675",
      "envelope": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
      "handshake_secret": "81263cb85a0cfa12450f0f388de4e92291ec4c7c7a0878b624550ff528726332f1298fc6cc822a432c89504347c7a2ccd70316ae3da6a15e0399e6db3f7c1b12",
      "masking_key": "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5",
      "oprf_key": "5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05",
      "randomized_password": "aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adeea73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9",
      "server_mac_key": "0d36b26cfe38f51f804f0a9361818f32ee1ce2a4e5578653b527184af058d3b2d8075c296fd84d24677913d1baa109290cd81a13ed383f9091a3804e65298dfc"
    },
    "outputs": {
      "KE1": "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326",
      "KE2": "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fedc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b671cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90",
      "KE3": "4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442",
      "export_key": "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",
      "registration_request": "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71",
      "registration_response": "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
      "registration_upload": "76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c36751ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5",
      "session_key": "42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc6731fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f"
    }
}
"""

vex = json.loads(vectors)

# run this if there is a change in the values of the test vectors
# ./testvecs2h.py >cfrg_test_vectors.h

print("#ifndef cfrg_test_vectors_h\n#define cfrg_test_vectors_h\n")
print("#include <stdint.h>\n")
for type in {"inputs", "intermediates", "outputs"}:
    for k, v in vex[type].items():
        print(f"#define {k.lower()}_len {len(v)//2}")
        print(
            f"const uint8_t {k.lower()}[{k.lower()}_len] = {{\n   %s}};\n" % ",\n   ".join(
                (", ".join((c for c in line if c)) for line in split_by_n(
                    (f"0x{x[0]}{x[1]}" for x in split_by_n(v,2))
                    ,8))
            ))
print("#endif")

# only run this code below if there is a change in the keys of the test vectors
# ./testvecs2h.py >cfrg_test_vector_decl.h

#print("#ifndef cfrg_test_vector_decl_h\n#define cfrg_test_vector_decl_h\n")
#print("#include <stdint.h>\n")
#for type in {"inputs", "intermediates", "outputs"}:
#    for k, v in vex[type].items():
#        print(f"#define {k.lower()}_len {len(v)//2}")
#        print(f"extern const uint8_t {k.lower()}[{k.lower()}_len];\n")
#print("#endif")

