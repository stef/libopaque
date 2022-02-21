package libopaque

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lopaque
// #include <stdlib.h>
// #include <opaque.h>
import "C"
import (
	"errors"
	"unsafe"
)

// Type wrapping the IDs of the user and the server
type OpaqueIDS struct {
	// users id
	IdU []byte
	// servers id
	IdS []byte
}

const OPAQUE_SHARED_SECRETBYTES = C.OPAQUE_SHARED_SECRETBYTES
const OPAQUE_ENVELOPE_NONCEBYTES = C.OPAQUE_ENVELOPE_NONCEBYTES
const OPAQUE_NONCE_BYTES = C.OPAQUE_NONCE_BYTES
const OPAQUE_REGISTRATION_RECORD_LEN = C.OPAQUE_REGISTRATION_RECORD_LEN
const OPAQUE_USER_RECORD_LEN = C.OPAQUE_USER_RECORD_LEN
const OPAQUE_USER_SESSION_PUBLIC_LEN = C.OPAQUE_USER_SESSION_PUBLIC_LEN
const OPAQUE_USER_SESSION_SECRET_LEN = C.OPAQUE_USER_SESSION_SECRET_LEN
const OPAQUE_SERVER_SESSION_LEN = C.OPAQUE_SERVER_SESSION_LEN
const OPAQUE_REGISTER_USER_SEC_LEN = C.OPAQUE_REGISTER_USER_SEC_LEN
const OPAQUE_REGISTER_PUBLIC_LEN = C.OPAQUE_REGISTER_PUBLIC_LEN
const OPAQUE_REGISTER_SECRET_LEN = C.OPAQUE_REGISTER_SECRET_LEN

// This function implements the storePwdFile function from the paper
// it is not specified by the RFC. This function runs on the server
// and creates a new output record rec of secret key material. The
// function accepts an optional long-term private key in the `skS`
// parameter. The server needs to implement the storage of this record
// and any binding to user names or as the paper suggests sid.
func Register(pwdU string, skS []byte, ids OpaqueIDS) ([]byte, []byte, error) {
	// int opaque_Register(
	//          const uint8_t *pwdU,
	//          const uint16_t pwdU_len,
	//          const uint8_t skS[crypto_scalarmult_SCALARBYTES],
	//          const Opaque_Ids *ids,
	// out:
	//          uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
	//          uint8_t export_key[crypto_hash_sha512_BYTES]);

	if len(ids.IdU) > (2 << 16) {
		return nil, nil, errors.New("idU too big")
	}
	if len(ids.IdS) > (2 << 16) {
		return nil, nil, errors.New("idS too big")
	}
	idCC := C.Opaque_Ids{
		idU:     (*C.uchar)(C.CBytes(ids.IdU)),
		idU_len: C.ushort(len(ids.IdU)),
		idS:     (*C.uchar)(C.CBytes(ids.IdS)),
		idS_len: C.ushort(len(ids.IdS)),
	}

	skS_ptr := (*C.uchar)(nil)
	if skS != nil {
		if len(skS) != C.crypto_scalarmult_SCALARBYTES {
			return nil, nil, errors.New("invalid skS")
		}
		skS_ptr = (*C.uchar)(C.CBytes(skS))
	}
	pwdB := []byte(pwdU)

	rec := C.malloc(C.OPAQUE_USER_RECORD_LEN)
	if rec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(rec))
	ek := C.malloc(C.crypto_hash_sha512_BYTES)
	if ek == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(ek))

	ret := C.opaque_Register(
		(*C.uchar)(C.CBytes(pwdB)),
		C.ushort(len(pwdB)),
		skS_ptr,
		&idCC,
		(*C.uchar)(rec),
		(*C.uchar)(ek),
	)
	if ret != 0 {
		return nil, nil, errors.New("Register failed")
	}

	r := C.GoBytes(rec, (C.int)(C.OPAQUE_USER_RECORD_LEN))
	e := C.GoBytes(ek, (C.crypto_hash_sha512_BYTES))
	return r, e, nil
}

// This function initiates a new OPAQUE session, is the same as the
// function defined in the paper with the name usrSession.
func CreateCredReq(pwdU string) ([]byte, []byte, error) {
	//int opaque_CreateCredentialRequest(
	// in:
	//          const uint8_t *pwdU, const uint16_t pwdU_len,
	// out:
	//          uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN+pwdU_len],
	//          uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);

	pwdB := []byte(pwdU)

	sec := C.malloc(C.OPAQUE_USER_SESSION_SECRET_LEN + C.ulong(len(pwdB)))
	if sec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sec))
	pub := C.malloc(C.OPAQUE_USER_SESSION_PUBLIC_LEN)
	if pub == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(pub))

	ret := C.opaque_CreateCredentialRequest(
		(*C.uchar)(C.CBytes(pwdB)),
		C.ushort(len(pwdB)),
		(*C.uchar)(sec),
		(*C.uchar)(pub),
	)
	if ret != 0 {
		return nil, nil, errors.New("CreateCredReq failed")
	}

	s := C.GoBytes(sec, (C.int)(C.OPAQUE_USER_SESSION_SECRET_LEN+len(pwdB)))
	p := C.GoBytes(pub, (C.OPAQUE_USER_SESSION_PUBLIC_LEN))
	return s, p, nil
}

// This is the same function as defined in the paper with name
// srvSession name. This function runs on the server and receives the
// output pub from the user running CreateCredReq(), furthermore the
// server needs to load the user record created when registering the
// user with Register() or StoreUserRec(). These input parameters are
// transformed into a secret/shared session key sk and a response resp
// to be sent back to the user.
func CreateCredResp(pub []byte, rec []byte, ids OpaqueIDS, context string) ([]byte, []byte, []byte, error) {
	// int opaque_CreateCredentialResponse(
	// in:
	//       const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
	//       const uint8_t rec[OPAQUE_USER_RECORD_LEN],
	//       const Opaque_Ids *ids,
	//       const uint8_t *context, size_t context_len
	// out:
	//       uint8_t resp[OPAQUE_SERVER_SESSION_LEN],
	//       uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
	//       uint8_t sec[crypto_auth_hmacsha512_BYTES]);

	if len(pub) != C.OPAQUE_USER_SESSION_PUBLIC_LEN {
		return nil, nil, nil, errors.New("invalid pub param")
	}

	ctxB := []byte(context)

	if len(ids.IdU) > (2 << 16) {
		return nil, nil, nil, errors.New("idU too big")
	}
	if len(ids.IdS) > (2 << 16) {
		return nil, nil, nil, errors.New("idS too big")
	}

	idCC := C.Opaque_Ids{
		idU:     (*C.uchar)(C.CBytes(ids.IdU)),
		idU_len: C.ushort(len(ids.IdU)),
		idS:     (*C.uchar)(C.CBytes(ids.IdS)),
		idS_len: C.ushort(len(ids.IdS)),
	}

	if len(rec) != (C.OPAQUE_USER_RECORD_LEN) {
		return nil, nil, nil, errors.New("invalid rec param")
	}

	resp := C.malloc(C.OPAQUE_SERVER_SESSION_LEN)
	if resp == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(resp))
	sk := C.malloc(C.OPAQUE_SHARED_SECRETBYTES)
	if sk == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sk))
	sec := C.malloc(C.crypto_auth_hmacsha512_BYTES)
	if sec == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sec))

	ret := C.opaque_CreateCredentialResponse(
		(*C.uchar)(C.CBytes(pub)),
		(*C.uchar)(C.CBytes(rec)),
		&idCC,
		(*C.uchar)(C.CBytes(ctxB)),
		C.ushort(len(ctxB)),
		(*C.uchar)(resp),
		(*C.uchar)(sk),
		(*C.uchar)(sec),
	)
	if ret != 0 {
		return nil, nil, nil, errors.New("CreateCredResp failed")
	}

	r := C.GoBytes(resp, (C.int)(C.OPAQUE_SERVER_SESSION_LEN))
	k := C.GoBytes(sk, (C.OPAQUE_SHARED_SECRETBYTES))
	s := C.GoBytes(sec, (C.crypto_auth_hmacsha512_BYTES))
	return r, k, s, nil
}

// This is the same function as defined in the paper with the
// usrSessionEnd name. It is run by the user and receives as input the
// response from the previous server CreateCredResp() function as well
// as the sec value from running the CreateCredReq() function
// that initiated this instantiation of this protocol, All these input
// parameters are transformed into a shared/secret session key pk,
// which should be the same as the one calculated by the
// CreateCredResp() function.
func RecoverCred(resp []byte, sec []byte, context string, ids OpaqueIDS) ([]byte, []byte, []byte, error) {
	// int opaque_RecoverCredentials(
	// in:
	//       const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
	//       const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
	//       const uint8_t *context, const size_t context_len,
	//       Opaque_Ids *ids,
	// out:
	//       uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
	//       uint8_t authU[crypto_auth_hmacsha512_BYTES],
	//       uint8_t export_key[crypto_hash_sha512_BYTES]);

	if len(resp) != C.OPAQUE_SERVER_SESSION_LEN {
		return nil, nil, nil, errors.New("invalid resp param")
	}

	if len(sec) <= C.OPAQUE_USER_SESSION_SECRET_LEN {
		return nil, nil, nil, errors.New("invalid sec param")
	}

	ctxB := []byte(context)

	// handle opaque ids
	if len(ids.IdU) > (2 << 16) {
		return nil, nil, nil, errors.New("idU too big")
	}
	if len(ids.IdS) > (2 << 16) {
		return nil, nil, nil, errors.New("idS too big")
	}

	idCC := C.Opaque_Ids{
		idU:     (*C.uchar)(C.CBytes(ids.IdU)),
		idU_len: C.ushort(len(ids.IdU)),
		idS:     (*C.uchar)(C.CBytes(ids.IdS)),
		idS_len: C.ushort(len(ids.IdS)),
	}

	sk := C.malloc(C.OPAQUE_SHARED_SECRETBYTES)
	if sk == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sk))
	authU := C.malloc(C.crypto_auth_hmacsha512_BYTES)
	if authU == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(authU))
	export_key := C.malloc(C.crypto_hash_sha512_BYTES)
	if export_key == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(export_key))

	ret := C.opaque_RecoverCredentials(
		(*C.uchar)(C.CBytes(resp)),
		(*C.uchar)(C.CBytes(sec)),
		(*C.uchar)(C.CBytes(ctxB)),
		C.ushort(len(ctxB)),
		&idCC,
		(*C.uchar)(sk),
		(*C.uchar)(authU),
		(*C.uchar)(export_key),
	)
	if ret != 0 {
		return nil, nil, nil, errors.New("recover creds failed")
	}

	s := C.GoBytes(sk, (C.int)(C.OPAQUE_SHARED_SECRETBYTES))
	a := C.GoBytes(authU, (C.crypto_auth_hmacsha512_BYTES))
	e := C.GoBytes(export_key, (C.crypto_hash_sha512_BYTES))
	return s, a, e, nil
}

// This is a function not explicitly specified in the original paper. In the
// irtf cfrg draft authentication is done using a hmac of the session
// transcript with different keys coming out of a hkdf after the key
// exchange.
func UserAuth(sec []byte, authU []byte) error {
	// int opaque_UserAuth(
	// in
	//       const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN],
	//       const uint8_t authU[crypto_auth_hmacsha512_BYTES]);

	if len(sec) != C.crypto_auth_hmacsha512_BYTES {
		return errors.New("invalid sec param")
	}
	if len(authU) != C.crypto_auth_hmacsha512_BYTES {
		return errors.New("invalid authU param")
	}

	ret := C.opaque_UserAuth(
		(*C.uchar)(C.CBytes(sec)),
		(*C.uchar)(C.CBytes(authU)),
	)
	if ret != 0 {
		return errors.New("user auth failed")
	}

	return nil
}

// Initial step to start registering a new user/client with the server.
// The user inputs its password pwdU, and receives a secret context sec
// and a blinded value M as output. sec should be protected until
// step 3 of this registration protocol and the value req should be
// passed to the server.
func CreateRegReq(pwdU string) ([]byte, []byte, error) {
	// int opaque_CreateRegistrationRequest(
	// int
	//        const uint8_t *pwdU,
	//        const uint16_t pwdU_len,
	// out
	//        uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len],
	//        uint8_t M[crypto_core_ristretto255_BYTES]);

	pwdB := []byte(pwdU)
	pwdU_len := C.ushort(len(pwdB))

	sec := C.malloc(C.OPAQUE_REGISTER_USER_SEC_LEN + C.ulong(pwdU_len))
	if sec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sec))

	M := C.malloc(C.crypto_core_ristretto255_BYTES)
	if M == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(M))

	ret := C.opaque_CreateRegistrationRequest(
		(*C.uchar)(C.CBytes(pwdB)),
		C.ushort(pwdU_len),
		(*C.uchar)(sec),
		(*C.uchar)(M),
	)
	if ret != 0 {
		return nil, nil, errors.New("create reg req failed")
	}

	s := C.GoBytes(sec, (C.int)(C.OPAQUE_REGISTER_USER_SEC_LEN+pwdU_len))
	m := C.GoBytes(M, (C.crypto_core_ristretto255_BYTES))
	return s, m, nil
}

// Server evaluates OPRF and creates a user-specific public/private keypair
//
// The server receives req from the users invocation of its
// CreateRegReq() function as well as an optional long-term
// private-key, it outputs a value sec which needs to be protected
// until step 4 by the server. This function also outputs a value resp
// which needs to be passed to the user.
func CreateRegResp(req []byte, skS []byte) ([]byte, []byte, error) {
	// int opaque_CreateRegistrationResponse(
	// in
	//        const uint8_t M[crypto_core_ristretto255_BYTES],
	//        const uint8_t skS[crypto_scalarmult_SCALARBYTES],
	// out
	//        uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	//        uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

	if len(req) != C.crypto_core_ristretto255_BYTES {
		return nil, nil, errors.New("invalid req param")
	}

	if skS != nil && len(skS) != C.crypto_scalarmult_SCALARBYTES {
		return nil, nil, errors.New("invalid pkS param")
	}

	sec := C.malloc(C.OPAQUE_REGISTER_SECRET_LEN)
	if sec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sec))

	resp := C.malloc(C.OPAQUE_REGISTER_PUBLIC_LEN)
	if resp == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(resp))

	ret := C.int(0)
	ret = C.opaque_CreateRegistrationResponse(
		(*C.uchar)(C.CBytes(req)),
		(*C.uchar)(C.CBytes(skS)),
		(*C.uchar)(sec),
		(*C.uchar)(resp))
	if ret != 0 {
		return nil, nil, errors.New("create reg resp failed")
	}

	s := C.GoBytes(sec, C.OPAQUE_REGISTER_SECRET_LEN)
	r := C.GoBytes(resp, C.OPAQUE_REGISTER_PUBLIC_LEN)
	return s, r, nil
}

// Final Registration step - server adds own info to the record to be stored.
//
// The rfc does not explicitly specify this function.  The server
// combines the sec value from its run of its CreateRegResp() function
// with the rec output of the users opaque_FinalizeRequest() function,
// creating the final record, which should be the same as the output
// of the 1-step storePwdFile() init function of the paper. The server
// should save this record in combination with a user id and/or sid
// value as suggested in the paper.
func FinalizeReq(sec []byte, resp []byte, ids OpaqueIDS) ([]byte, []byte, error) {
	// int opaque_FinalizeRequest(
	// in
	//       const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/],
	//       const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
	//       const Opaque_Ids *ids,
	// out
	//       uint8_t rec[OPAQUE_REGISTRATION_RECORD_LEN],
	//       uint8_t export_key[crypto_hash_sha512_BYTES]);
	if len(sec) <= C.OPAQUE_REGISTER_USER_SEC_LEN {
		return nil, nil, errors.New("invalid sec param")
	}
	if len(resp) != C.OPAQUE_REGISTER_PUBLIC_LEN {
		return nil, nil, errors.New("invalid resp param")
	}

	if len(ids.IdU) > (2 << 16) {
		return nil, nil, errors.New("idU too big")
	}
	if len(ids.IdS) > (2 << 16) {
		return nil, nil, errors.New("idS too big")
	}
	idCC := C.Opaque_Ids{
		idU:     (*C.uchar)(C.CBytes(ids.IdU)),
		idU_len: C.ushort(len(ids.IdU)),
		idS:     (*C.uchar)(C.CBytes(ids.IdS)),
		idS_len: C.ushort(len(ids.IdS)),
	}

	rec := C.malloc(C.OPAQUE_REGISTRATION_RECORD_LEN)
	if rec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(rec))

	ek := C.malloc(C.crypto_hash_sha512_BYTES)
	if ek == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(ek))

	ret := C.opaque_FinalizeRequest(
		(*C.uchar)(C.CBytes(sec)),
		(*C.uchar)(C.CBytes(resp)),
		&idCC,
		(*C.uchar)(rec),
		(*C.uchar)(ek),
	)
	if ret != 0 {
		return nil, nil, errors.New("finalize req failed")
	}

	r := C.GoBytes(rec, (C.int)(C.OPAQUE_REGISTRATION_RECORD_LEN))
	e := C.GoBytes(ek, (C.crypto_hash_sha512_BYTES))
	return r, e, nil
}

// Final Registration step Global Server Key Version - server adds own
// info to the record to be stored.
//
// The server combines the sec value from its run of its
// CreateRegResp() function with the rec output of the users
// FinalizeReq() function, creating the final record, which should be
// the same as the output of the 1-step storePwdFile() init function
// of the paper. The server should save this record in combination
// with a user id and/or sid value as suggested in the paper.
func StoreUserRec(sec []byte, recU []byte) ([]byte, error) {
	// void opaque_StoreUserRecord(
	// in
	//       const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	//       uint8_t recU[OPAQUE_REGISTRATION_RECORD_LEN]);
	// out
	//       uint8_t rec[OPAQUE_USER_RECORD_LEN]);

	if len(sec) != C.OPAQUE_REGISTER_SECRET_LEN {
		return nil, errors.New("invalid sec param")
	}

	if len(recU) != C.OPAQUE_REGISTRATION_RECORD_LEN {
		return nil, errors.New("invalid recU param")
	}

	//uint8_t rec[OPAQUE_USER_RECORD_LEN]
	rec := C.malloc(C.OPAQUE_USER_RECORD_LEN)
	if rec == nil {
		return nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(rec))

	C.opaque_StoreUserRecord(
		(*C.uchar)(C.CBytes(sec)),
		(*C.uchar)(C.CBytes(recU)),
		(*C.uchar)(rec),
	)

	r := C.GoBytes(rec, (C.int)(C.OPAQUE_USER_RECORD_LEN))
	return r, nil
}
