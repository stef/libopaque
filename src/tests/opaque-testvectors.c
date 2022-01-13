/*
    @copyright 2018-2020, opaque@ctrlc.hu
    This file is part of libopaque

    libopaque is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libopaque is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libopaque. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <assert.h>
#include "../opaque.h"
#include "../common.h"

//static void _dump(const uint8_t *p, const size_t len, const char* msg) {
//  size_t i;
//  printf("%s",msg);
//  for(i=0;i<len;i++)
//    printf("%02x", p[i]);
//  printf("\n");
//}

int main(void) {
#ifdef VOPRF_TEST_VEC_1
  const unsigned char input[] = {
   0x00
  };
  const unsigned int input_len = 1;
#elif VOPRF_TEST_VEC_2
  const unsigned char input[] = {
   0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a
  };
  const unsigned int input_len = 17;
#endif

  //const unsigned char info[] = {
  // 0x4f, 0x50, 0x52, 0x46, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65,
  // 0x63, 0x74, 0x6f, 0x72, 0x73
  //};
  //const unsigned int info_len = 17;

  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+input_len];
  uint8_t alpha[crypto_core_ristretto255_BYTES];

  if(0!=opaque_CreateRegistrationRequest(input, input_len, usr_ctx, alpha)) return 1;

  unsigned char rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
  if(0!=opaque_CreateRegistrationResponse(alpha, rsec, rpub)) return 1;

  unsigned char rrec[OPAQUE_USER_RECORD_LEN+input_len];
  uint8_t export_key[crypto_hash_sha512_BYTES];
  Opaque_Ids ids={4,(uint8_t*)"user",6,(uint8_t*)"server"};
  ids.idU_len = strlen((char*) ids.idU);
  ids.idS_len = strlen((char*) ids.idS);
  Opaque_PkgConfig cfg={
                        .skU = InSecEnv,
                        .pkU = InSecEnv,
                        .pkS = InSecEnv,
                        .idS = InSecEnv,
                        .idU = InSecEnv,
  };
  if(0!=opaque_FinalizeRequest(usr_ctx, rpub, &cfg, &ids, rrec, export_key)) return 1;

  return 0;
}

