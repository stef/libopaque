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
      "OPRF": "0001"
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
      "auth_key": "41f7bcf84440b1fc5a22784ed336bdd19826b75c27da9bf632f3ea31d35ecd40dd0a4ce2efd65d626ac2fdf314a67a9677a639973a55ad0a8d25376f977f5850",
      "client_mac_key": "5e5155d5c50d05523a5286e7f8184e8ccff106b35ef6ff9bffe15e3e9e523ba883ab221a723a63423e66a4131c2d78500c2a4f5b482650a3c77cc084d07d2e48",
      "client_public_key": "56e3eba164846e1f6f7aadc1fcce5afcce2873c8724b403ebbd1cc28c140c408",
      "envelope": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb40dfd4af6c87612aa101dbc7d1909daaa8eb8922801f6b63e4592ec93a35332e86e637b465dea3b6654a0f2b935a37a27d33f020b48ac96318e6cd1accc0ddb",
      "handshake_secret": "8da21427b9339f06075adbbdb5672b9b470793dd151875a63f397e87454d2760e46c5db71f476aa2b18feb5f6c16dcf40b3bc7bf4d0f235e62bfe3f620838fc8",
      "masking_key": "5f7e4678e84c3004cb1c07ba9e5127b0734c65011caad9562a2e1ca3dd9ad5584719a4df8c5427b19ff759b4d2de473019232720498f0d4f7f76b03af304ceb2",
      "oprf_key": "3731ddbbaafc56d3b4b596a9b07d67c9e8f9b2c1723db7eaef0b33230aced905",
      "randomized_pwd": "5987bf92fadc6ed1e191ecd46ed735371a02e119dd0a31b9be150f77b30f9a89d0544ee204c96846b1b7b81767fa7fe632f1d2c5629baf50fd99bcca8eed2ea1",
      "server_mac_key": "7a7aabf7033b982d5b5eb313bd963c35118a5acabacdaa3889e51295088a40f793ec2ecbd94b868d8e6c05eb3cb5a3b4c11dfafd39ebca3c53c65ebc43d2723d"
    },
    "outputs": {
      "KE1": "42f05c7bb835096ae3b27df8df9a55353efff6126a896cc5602da673c25b8e4fda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663",
      "KE2": "56508680233c0a3f1d60108490587baad9f6595c2dcffd673d32c632538bf90c38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6da9c05771412c97662d617d7aed65995ffefae3aa9ce51fa4bd49e53c28b195d11b088df760e0fb9a088eb662160784889fad2ce8f0e38bfe4841e36f3808fc0f0459c9d38b6eade3a40d47e8b09fe005884fbabd7b2ae6cbdc57042e6dd0a8847c403df73a546cd181f6957035d95e479415ba01df1711962aff54cf87b2d10471cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe40280fdddcba811a8c8913341fd6bf33f81b4ad7cb9cbad2eb9a3e10635c8e1d289aebf05d78e8e6dbd196db7ec02dfc2e12646ceffa1fd483f4e4ffb81ed751df04",
      "KE3": "9f5a91d80740458c718b2a73b93d2677db26a809f960f809b5f90cc5706f2866b4ac3b85f38df2752681733e43673dd0cf08d9600bcdbf8d548e95661ae41c71",
      "export_key": "6ad4ebd8b6ec2392aa2a73c968885f6fd4316d40847cda022b7aa93019b9edbb726995811265fceab3bc44de78318aca26e24488c9f1ed1a44b46f836a6349ba",
      "registration_request": "46993e4d9ad14959fd882072d5cd4f61529aeaa7d568869ea7a640d48af0a04e",
      "registration_response": "b05f44c47dc6c2f1364acc9fbec30dfcd970915429d66edbdf879778ee982769b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
      "registration_upload": "56e3eba164846e1f6f7aadc1fcce5afcce2873c8724b403ebbd1cc28c140c4085f7e4678e84c3004cb1c07ba9e5127b0734c65011caad9562a2e1ca3dd9ad5584719a4df8c5427b19ff759b4d2de473019232720498f0d4f7f76b03af304ceb2ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfecb40dfd4af6c87612aa101dbc7d1909daaa8eb8922801f6b63e4592ec93a35332e86e637b465dea3b6654a0f2b935a37a27d33f020b48ac96318e6cd1accc0ddb",
      "session_key": "5a10ffb0d1a4bcd9e93bdcb912064d2cf5980d3d59e085afcdc73ebe8dfa0126abde0a2016c5ef9df3e42a503dd88ff1bd287f8568a86831a143dc258233269c"
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

