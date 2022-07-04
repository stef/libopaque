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
      "auth_key": "e1ff65c196e1c4b4bf46361798eec479b318831329680f33b4f77ad49d8c6e6ef49d87082d654d21f2e36454582353fefc23c07637bd8ca4aa88a4461ea96d6c",
      "client_mac_key": "4d4d4c4b8b35501876ed01d07f5718357ff720163b84813b1bde4f3b6ca3e1de744a267e3d145e6095a0e5b1617714e10af7e10093d0ba8dd115e6bdb1f5ccd9",
      "client_public_key": "8e5e5c04b2154336fa52ac691eb6df5f59ec7315b8467b0bba1ed4f413043b44",
      "envelope": "ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec8e8bde8d4eb9e171240b3d2dfb43ef93efe5cd15412614b3df11ecb58890047e2fa31c283e7c58c40495226cfa0ed7756e493431b85c464aad7fdaaf1ab41ac7",
      "handshake_secret": "885a0a7bd8e704d8fc26f62b8657f8c5d01ffb35b27ad538493968dcf6dba7a2d42d404d6ed6a87805a030ffafe791fb69fd044c1ac152ee0ee78853cebb0700",
      "masking_key": "9afea0ddedbbce5c083c5d5d02aa5218bcc7100f541d841bb5974f084f7aa0b929399feb39efd17e13ce1035cbb23251da3b5126a574b239c7b73519d8847e2f",
      "oprf_key": "6c246eaa55e47d0490ffa8a6f784e803eed9384a250458def36a2acebf15c905",
      "randomized_pwd": "4386bf4b83db06f47672fd60b4cface554558da7be3c616c56b2ed29b544d1b50bc45893b1c05d8d6866a9bbe91395e4704740be58728e8872352f56d5319f8f",
      "server_mac_key": "d29e33eb506fbf199c818d1300e7253404a7d5de9c660a90f79afe4cc15da2ae31e511c6eb1c4df95f47c9759606732781a3d1884a4d53cba690bdb9e9ac4d7c"
    },
    "outputs": {
      "KE1": "1670c409ebb699a6012629451d218d42a34eddba1d2978536c45e199c60a0b4eda7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc0c3a00c961fead8a16f818929cc976f0475e4f723519318b96f4947a7a5f9663",
      "KE2": "36b4d06f413b72004392d7359cd6a998c667533203d6a671afe81ca09a282f7238fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d378cc6b0113bf0b6afd9e0728e62ba793d5d25bb97794c154d036bf09c98c472368bffc4e35b7dc48f5a32dd3fede3b9e563f7a170d0e082d02c0a105cdf1ee0ea1928202076ff37ce174f2c669d52d8adc424e925a3bc9a4ca5ce16d9b7a1791ff7e47a0d2fa42424e5476f8cfa7bb20b2796ad877295a996ffcb049313f4e971cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1c8c39f573135474c51660b02425bca633e339cec4e1acc69c94dd48497fe402848f3b062916ea7666973222944dabe1027e5bea84b1b5d46dab64b1c6eda3170d4c9adba8afa61eb4153061d528b39102f32ecda7d7625dbc229e6630a607e03",
      "KE3": "4e23f0f84a5261918a7fc23bf1978a935cf4e320d56984079f8c7f4a54847b9e979f519928c5898927cf6aa8d51ac42dc2d0f5840956caa3a34dbc55ce74415f",
      "export_key": "403a270110164ae0de7ea77c6824343211e8c1663ccaedde908dc9acf661039a379c8ac7e4b0cb23a8d1375ae94a772f91536de131d9d86633cb9445f773dfac",
      "registration_request": "62235332ae15911d69812e9eeb6ac8fe4fa0ffc7590831d5c5e1631e01049276",
      "registration_response": "6268d13fea98ebc8e6b88d0b3cc8a78d2ac8fa8efc741cd2e966940c52c31c71b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78",
      "registration_upload": "8e5e5c04b2154336fa52ac691eb6df5f59ec7315b8467b0bba1ed4f413043b449afea0ddedbbce5c083c5d5d02aa5218bcc7100f541d841bb5974f084f7aa0b929399feb39efd17e13ce1035cbb23251da3b5126a574b239c7b73519d8847e2fac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec8e8bde8d4eb9e171240b3d2dfb43ef93efe5cd15412614b3df11ecb58890047e2fa31c283e7c58c40495226cfa0ed7756e493431b85c464aad7fdaaf1ab41ac7",
      "session_key": "d2dea308255aa3cecf72bcd6ac96ff7ab2e8bad0494b90180ad340b7d8942a36ee358e76c372790d4a5c1ac900997ea2abbf35f2d65510f8dfd668e593b8e1fe"
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

