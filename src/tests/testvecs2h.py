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
      "client_keyshare": "0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663",
      "client_nonce": "da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc",
      "client_private_keyshare": "22c919134c9bdd9dc0c5ef3450f18b54820f43f646a95223bf4a85b2018c2001",
      "credential_identifier": "31323334",
      "envelope_nonce": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec",
      "masking_nonce": "38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d",
      "oprf_seed": "f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fdc65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef",
      "password": "436f7272656374486f72736542617474657279537461706c65",
      "server_keyshare": "c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe4028",
      "server_nonce": "71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1",
      "server_private_key": "47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d",
      "server_private_keyshare": "2e842960258a95e28bcfef489cffd19d8ec99cc1375d840f96936da7dbb0b40d",
      "server_public_key": "b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"
    },
    "intermediates": {
      "auth_key": "6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494fc555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822",
      "client_mac_key": "f2d019bad603b45b2ac50376279a0a37d097723b5405aa4fb20a59f60cdbdd52ec043372cedcdbbdb634c54483e1be51a88d13a5798180acb84c10b1297069fd",
      "client_public_key": "2ec892bdbf9b3e2ea834be9eb11f5d187e64ba661ec041c0a3b66db8b7d6cc30",
      "envelope": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb9dbe7d48cf714fc3533becab6faf60b783c94d258477eb74ecc453413bf61c53fd58f0fb3c1175410b674c02e1b59b2d729a865b709db3dc4ee2bb45703d5a8",
      "handshake_secret": "562564da0d4efdc73cb6efbb454388dabfa5052d4e7e83f4d0240c5afd8352881e762755c2f1a9110e36b05fe770f0f48658489c9730dcd365e6c2d4049c8fe3",
      "masking_key": "1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5",
      "oprf_key": "5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05",
      "randomized_pwd": "aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adeea73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9",
      "server_mac_key": "59473632c53a647f9f4ab4d6c3b81e241dd9cb19ca05f0eabed7e593f0407ff57e7f060621e5e48d5291be600a1959fbecbc26d4a7157bd227a993c37b645f73"
    },
    "outputs": {
      "KE1": "c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44dda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663",
      "KE2": "7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb47138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6dd6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe0610f003be80cb2098357928c8ea17bb065af33095f39d4e0b53b1687f02d522d96bad4ca354293d5c401177ccbd302cf565b96c327f71bc9eaf2890675d2fbb71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe40287f33611c2cf0eef57adbf48942737d9421e6b20e4b9d6e391d4168bf4bf96ea57aa42ad41c977605e027a9ef706a349f4b2919fe3562c8e86c4eeecf2f9457d4",
      "KE3": "df9a13cd256091f90f0fcb2ef6b3411e4aebff07bb0813299c0ec7f5dedd33a7681231a001a82f1dece1777921f42abfeee551ee34392e1c9743c5cc1dc1ef8c",
      "export_key": "1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16",
      "registration_request": "5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71",
      "registration_response": "7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
      "registration_upload": "2ec892bdbf9b3e2ea834be9eb11f5d187e64ba661ec041c0a3b66db8b7d6cc301ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb95864eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb9dbe7d48cf714fc3533becab6faf60b783c94d258477eb74ecc453413bf61c53fd58f0fb3c1175410b674c02e1b59b2d729a865b709db3dc4ee2bb45703d5a8",
      "session_key": "8a0f9f4928fc0c3b5bb261c4b7b3997600405424a8128632e85a5667b4b742484ed791933971be6d3fcf2b23c56b8e8f7e7edcae19a03b8fd87f5999fce129d2"
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

