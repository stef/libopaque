package main

// a simple example of how to set up an encrypted channel between a
// client and server using the OPAQUE protocol this file implements
// the server in go. It creates a simple server that listens for
// incoming requests, tries to respond using OPAQUE and exchanges a
// message using the session key derived using OPAQUE.

import (
	"encoding/hex"
	"fmt"
	"github.com/jamesruan/sodium"
	"github.com/stef/libopaque/go"
	"net"
)

func main() {
	// some boilerplate to have a server responding
	fmt.Println("listening")
	l, err := net.Listen("tcp", ":1337")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	// a hardcoded OPAQUE user record, it opens up with the password: "password"
	rec, err := hex.DecodeString("7a3c6282f02d37a05023b60d5428e6cc5961d4c31221937adae0b574e4d07205000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc8485b707c63275ec0ca1af4480fb84c3c3ca6984aecbfb1a86d1782b5cccf005f206357c4f6e718c15dd6575e54b8b1fdd94a2b050261f5e12b94587c4d258c68fe296966007b462627b572b17f3a91897d994fadb4ad54946539d0f02550d0000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe79b50b65fe2b00c48522c0343c92a1d8f8587b0e6a5729690a663babd7dc43eeb7e71fb9b2af2b0185e45c36ab67fd483e9cb9f6296021af6773e2403faad15")
	if err != nil {
		panic(err)
	}

	// these are the ids also used by the client, they must match
	ids := libopaque.OpaqueIDS{
		IdU: []byte("user"),
		IdS: []byte("server"),
	}

	// the context must also match with the client
	context := "context"

	// handle any incoming request
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		request := make([]byte, libopaque.OPAQUE_USER_SESSION_PUBLIC_LEN)
		b, err := c.Read(request)
		if err != nil || b != libopaque.OPAQUE_USER_SESSION_PUBLIC_LEN {
			fmt.Println(b)
			panic(err)
		}

		// create a response based on the request, the hard-coded user
		// record, the ids and the context.
		resp, sk, _, err := libopaque.CreateCredResp(request, rec, ids, context)
		if err != nil {
			panic(err)
		}

		// send the response over
		b, err = c.Write(resp)
		if err != nil || b != libopaque.OPAQUE_SERVER_SESSION_LEN {
			fmt.Println(b)
			panic(err)
		}

		// just a dummy fixed size message expected
		msg := make([]byte, 24+32+16)
		b, err = c.Read(msg)
		if err != nil || b != 24+32+16 {
			fmt.Println(b)
			panic(err)
		}

		// decrypt the message using the shared session key sk
		msg, err = sodium.Bytes(msg[24:]).SecretBoxOpen(sodium.SecretBoxNonce{msg[:24]}, sodium.SecretBoxKey{sk[:32]})
		if err != nil {
			fmt.Println("failed to decrypt message")
			panic(err)
		}
		fmt.Println("got message:", string(msg))

		// create an answer message and encrypt it with the shared
		// session key sk
		n := sodium.SecretBoxNonce{}
		sodium.Randomize(&n)
		response := "msg acknowledged. Hello World!!\x00"

		ct := sodium.Bytes([]byte(response)).SecretBox(n, sodium.SecretBoxKey{sk[:32]})

		// send the answer
		c.Write(n.Bytes)
		c.Write(ct)
		// and close the connection
		c.Close()
	}
}
