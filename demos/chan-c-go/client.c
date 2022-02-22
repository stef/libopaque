// a simple demo client showing how to establish a secure channel with
// a server using OPAQUE
// compile it with:
// gcc -Wall -o client client.c -lsodium -lopaque

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sodium.h>
#include "opaque.h"

// this function implements the client-side OPAQUE steps,
// it requires a socket to the server,
// a password unlocking the OPAQUE user record
// and it returns a shared session key.
int get_session_secret(const int sock,
                       const uint8_t *pwdU,
                       const size_t pwdU_len,
                       uint8_t sk[OPAQUE_SHARED_SECRETBYTES]) {

  // let's prepare to make create a credential request, we need some
  // data to store it in:
  uint8_t request[OPAQUE_USER_SESSION_PUBLIC_LEN];
  uint8_t ctx[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len];
  // ctx is sensitive data we should protect it! with c you can
  // actually protect sensitive data much better than with other
  // languages, sodium wraps this up nicely and portably:
  if(-1==sodium_mlock(ctx,sizeof ctx)) {
    fprintf(stderr,"Failed to protect sensitive context\n");
    return -1;
  }

  // let's create the credential request
  if(0!=opaque_CreateCredentialRequest(pwdU, pwdU_len, ctx, request)) {
    fprintf(stderr,"Failed to create credential request\n");
    return -1;
  }

  // send off the request to the server
  if(sizeof request != write(sock, request, sizeof request)) {
    //fprintf(stderr,);
    perror("failed to send the request\n");
    return -1;
  }

  // we need to store the servers response
  uint8_t response[OPAQUE_SERVER_SESSION_LEN];
  // receive a response from the server
  if(sizeof response != read(sock, response, sizeof response )) {
    perror("failed to read the response\n");
    return -1;
  }

  // we need to supply the same context and user ids to the final step
  // as have been used by the server
  const uint8_t context[]="context";
  const Opaque_Ids ids={4,(uint8_t*) "user",6,(uint8_t*)"server"};
  // we recover the shared session key, and we set the authorization
  // token and the export_key parameters to NULL since we do not care
  // about them in this demo.
  if(0!=opaque_RecoverCredentials(response, ctx, context, strlen((char*)context), &ids, sk, NULL, NULL)) {
    fprintf(stderr,"Failed to recovercredential\n");
    return 1;
  }
  // yay everything went fine.
  return 0;
}

int main(int argc, char** argv) {
   if(argc!=3) {
      fprintf(stderr,"%s \"password\" \"ip-addr\"\n", argv[0]);
      exit(1);
   }

   // boiler-plate setting up a tcp connection with the server
   int sock;
   struct sockaddr_in addr = {
                              .sin_family = AF_INET,
                              .sin_port = htons(1337),
                              .sin_addr.s_addr = inet_addr(argv[2]),
                              .sin_zero = {0}
   };
   sock = socket(PF_INET, SOCK_STREAM, 0);
   if(sock<0) {
     perror("failed socket call\n");
     return 1;
   }
   if(0!=connect(sock, (struct sockaddr *) &addr, sizeof addr)) {
     perror("failed to connect\n");
     return 1;
   }
   // we are connected, let's do OPAQUE to establish a shared session
   // key with the server:
   uint8_t sk[OPAQUE_SHARED_SECRETBYTES];
   if(0!=get_session_secret(sock, (uint8_t*) argv[1], strlen(argv[1]),  sk)) {
      fprintf(stderr,"something went wrong establishing session secret\n");
      exit(1);
   }

   // Now use the shared session key to exchange some messages
   struct { uint8_t nonce[24]; uint8_t msg[32]; uint8_t mac[16]; } pkt = { .msg = {0} };
   const int ct_size=sizeof pkt - sizeof pkt.nonce;
   memcpy(pkt.msg, &"a secret message", 16);
   randombytes_buf(pkt.nonce, sizeof pkt.nonce);
   crypto_secretbox_easy(pkt.msg, pkt.msg, sizeof pkt.msg, pkt.nonce, sk);
   // pkt now contains an encrypted message using the shared session key

   // send the encrypted messsage over
   if(sizeof pkt != write(sock, &pkt, sizeof pkt)) {
     perror("failed to send the secret message\n");
     return -1;
   }

   // receive an answer, first a nonce
   if(sizeof pkt.nonce != read(sock, &pkt, sizeof pkt.nonce)) {
     perror("failed to read the nonce res");
     return -1;
   }

   // and the encrypted answer
   if(ct_size != read(sock, &pkt.msg, ct_size)) {
     perror("failed to read the response res");
     return -1;
   }

   // try to decrypt the answer
   if(0!=crypto_secretbox_open_easy(pkt.msg, pkt.msg, ct_size, pkt.nonce, sk)) {
     fprintf(stderr,"failed to decrypt the response\n");
     return -1;
   }

   // all is good, the message is:
   printf("received message: \"%s\"\n", pkt.msg);

   return 0;
}
