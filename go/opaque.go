package libopaque

// #cgo CFLAGS: -g -Wall
// #cgo LDFLAGS: -lopaque
// #include <stdlib.h>
// #include <opaque.h>
// #include "libopaque.h"
import "C"
import (
	"errors"
	"unsafe"
)

// Type wrapping the infos parameter, it is not very well specified,
// see the irtf cfrg draft for more info
type OpaqueInfos struct {
	Info  []byte
	Einfo []byte
}

// Type wrapping the IDs of the user and the server
type OpaqueIDS struct {
	// users id
	IdU []byte
	// servers id
	IdS []byte
}

const (
	// field is not included in the envelope
	CfgNotPackaged C.int = C.NotPackaged
	// field is encrypted and authenticated in the envelope
	CfgInSecEnv C.int = C.InSecEnv
	// field is plaintext but authenticated in the envelop
	CfgInClrEnv C.int = C.InClrEnv
)

// Type to store an OPAQUE envelop configuration
type OpaqueCfg struct {
	// users secret key - must not be InClrEnv, if it is NotPackaged
	// then rwdU is used to seed a keygen() via hkdf-expand()
	SkU C.int
	// users public key - if not included it can be derived from the
	// private key
	PkU C.int
	// servers public key - if not packaged it must be supplied to the
	// functions requiring this (see the pkS param)
	PkS C.int
	// id of the user
	IdU C.int
	// id of the server
	IdS C.int
}

// private internal function converting an OpaqueCfg to the packed 2
// byte c struct that libopaque expects.
func createConfig(c OpaqueCfg) (C.Opaque_PkgConfig, error) {
	cfg := C.Opaque_PkgConfig{}

	if c.SkU == CfgInClrEnv {
		return cfg, errors.New("skU cannot be CfgInClrEnv")
	}

	ret := C.create_cfg(c.SkU, c.PkU, c.PkS, c.IdU, c.IdS, &cfg)
	if ret != 0 {
		return cfg, errors.New("failed to create config")
	}
	return cfg, nil
}

// This function implements the storePwdFile function from the paper
// it is not specified by the RFC. This function runs on the server
// and creates a new output record rec of secret key material. The
// server needs to implement the storage of this record and any
// binding to user names or as the paper suggests sid.
func Register(pwdU string, skS []byte, cfg_ OpaqueCfg, ids OpaqueIDS) ([]byte, []byte, error) {
	// int opaque_Register(
	//          const uint8_t *pwdU,
	//          const uint16_t pwdU_len,
	//          const uint8_t skS[crypto_scalarmult_SCALARBYTES],
	//          const Opaque_PkgConfig *cfg,
	//          const Opaque_Ids *ids,
	// out:
	//          uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
	//          uint8_t export_key[crypto_hash_sha256_BYTES]);

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

	if (skS != nil) && (len(skS) != C.crypto_scalarmult_SCALARBYTES) {
		return nil, nil, errors.New("invalid skS")
	}

	pwdB := []byte(pwdU)

	cfg, err := createConfig(cfg_)
	if err != nil {
		return nil, nil, errors.New("bad cfg")
	}

	envU_len := C.opaque_envelope_len(&cfg, &idCC)
	rec := C.malloc(C.sizeof_char * (C.OPAQUE_USER_RECORD_LEN + envU_len))
	if rec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(rec))
	ek := C.malloc(C.sizeof_char * C.crypto_hash_sha256_BYTES)
	if ek == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(ek))

	ret := C.opaque_Register(
		(*C.uchar)(C.CBytes(pwdB)),
		C.ushort(len(pwdB)),
		(*C.uchar)(C.CBytes(skS)),
		&cfg,
		&idCC,
		(*C.uchar)(rec),
		(*C.uchar)(ek),
	)
	if ret != 0 {
		return nil, nil, errors.New("Register failed")
	}

	r := C.GoBytes(rec, (C.int)(C.OPAQUE_USER_RECORD_LEN+envU_len))
	e := C.GoBytes(ek, (C.crypto_hash_sha256_BYTES))
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
func CreateCredResp(pub []byte, rec []byte, cfg_ OpaqueCfg, ids OpaqueIDS, infos OpaqueInfos) ([]byte, []byte, []byte, error) {
	// int opaque_CreateCredentialResponse(
	// in:
	//       const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN],
	//       const uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
	//       const Opaque_Ids *ids,
	//       const Opaque_App_Infos *infos,
	// out:
	//       uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
	//       uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
	//       uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN]);

	if len(pub) != C.OPAQUE_USER_SESSION_PUBLIC_LEN {
		return nil, nil, nil, errors.New("invalid pub param")
	}

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

	infoC := C.Opaque_App_Infos{
		info:      (*C.uchar)(C.CBytes(infos.Info)),
		info_len:  C.ulong(len(infos.Info)),
		einfo:     (*C.uchar)(C.CBytes(infos.Einfo)),
		einfo_len: C.ulong(len(infos.Einfo)),
	}

	cfg, err := createConfig(cfg_)
	if err != nil {
		return nil, nil, nil, errors.New("bad cfg")
	}

	envU_len := C.opaque_envelope_len(&cfg, &idCC)

	if len(rec) != (C.OPAQUE_USER_RECORD_LEN + int(envU_len)) {
		return nil, nil, nil, errors.New("invalid pub param")
	}

	resp := C.malloc(C.OPAQUE_SERVER_SESSION_LEN + envU_len)
	if resp == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(resp))
	sk := C.malloc(C.OPAQUE_SHARED_SECRETBYTES)
	if sk == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sk))
	sec := C.malloc(C.OPAQUE_SERVER_AUTH_CTX_LEN)
	if sec == nil {
		return nil, nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sec))

	ret := C.opaque_CreateCredentialResponse(
		(*C.uchar)(C.CBytes(pub)),
		(*C.uchar)(C.CBytes(rec)),
		&idCC,
		&infoC,
		(*C.uchar)(resp),
		(*C.uchar)(sk),
		(*C.uchar)(sec),
	)
	if ret != 0 {
		return nil, nil, nil, errors.New("CreateCredResp failed")
	}

	r := C.GoBytes(resp, (C.int)(C.OPAQUE_SERVER_SESSION_LEN+envU_len))
	k := C.GoBytes(sk, (C.OPAQUE_SHARED_SECRETBYTES))
	s := C.GoBytes(sec, (C.OPAQUE_SERVER_AUTH_CTX_LEN))
	return r, k, s, nil
}

// This is the same function as defined in the paper with the
// usrSessionEnd name. It is run by the user and receives as input the
// response from the previous server CreateCredResp() function as well
// as the sec value from running the CreateCredReq() function that
// initiated this instantiation of this protocol, All these input
// parameters are transformed into a shared/secret session key pk,
// which should be the same as the one calculated by the
// CreateCredResp() function.
func RecoverCred(resp []byte, sec []byte, pkS []byte, cfg_ OpaqueCfg, ids OpaqueIDS, infos OpaqueInfos) ([]byte, []byte, []byte, OpaqueIDS, error) {
	// int opaque_RecoverCredentials(
	// in:
	//       const uint8_t resp[OPAQUE_SERVER_SESSION_LEN/*+envU_len*/],
	//       const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN/*+pwdU_len*/],
	//       const uint8_t pkS[crypto_scalarmult_BYTES],
	//       const Opaque_PkgConfig *cfg,
	//       const Opaque_App_Infos *infos,
	// io:   Opaque_Ids *ids,
	// out:
	//       uint8_t sk[OPAQUE_SHARED_SECRETBYTES],
	//       uint8_t authU[crypto_auth_hmacsha256_BYTES],
	//       uint8_t export_key[crypto_hash_sha256_BYTES]);

	if len(sec) <= C.OPAQUE_USER_SESSION_SECRET_LEN {
		return nil, nil, nil, ids, errors.New("invalid sec param")
	}

	// handle opaque ids - they are in/out params in recover cred

	idCC := C.Opaque_Ids{}
	idU_buf := unsafe.Pointer(nil)
	idS_buf := unsafe.Pointer(nil)

	if len(ids.IdU) >= (2 << 16) {
		return nil, nil, nil, ids, errors.New("idU too big")
	}
	if len(ids.IdU) > 0 {
		if cfg_.IdU != CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("redundant idU")
		}
		idCC.idU = (*C.uchar)(C.CBytes(ids.IdU))
		idCC.idU_len = C.ushort(len(ids.IdU))
	} else {
		if cfg_.IdU == CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("missing idU")
		}
		idU_buf = C.calloc(65535, 1)
		if idU_buf == nil {
			return nil, nil, nil, ids, errors.New("missing idU")
		}
		idCC.idU = (*C.uchar)(idU_buf)
		idCC.idU_len = 65535
	}
	//fmt.Printf("> idCC.idU(%d): %s\n", C.int(idCC.idU_len),
	//	C.GoBytes(unsafe.Pointer(idCC.idU), (C.int)(idCC.idU_len)))
	defer C.free(unsafe.Pointer(idU_buf))

	if len(ids.IdS) >= (2 << 16) {
		return nil, nil, nil, ids, errors.New("idS too big")
	}
	if len(ids.IdS) > 0 {
		if cfg_.IdS != CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("redundant idS")
		}
		idCC.idS = (*C.uchar)(C.CBytes(ids.IdS))
		idCC.idS_len = C.ushort(len(ids.IdS))
	} else {
		if cfg_.IdS == CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("missing idS")
		}
		idS_buf := C.calloc(65535, 1)
		if idU_buf == nil {
			return nil, nil, nil, ids, errors.New("missing idU")
		}
		idCC.idS = (*C.uchar)(idS_buf)
		idCC.idS_len = 65535
	}
	defer C.free(unsafe.Pointer(idS_buf))

	// handle infos struct

	infoC := C.Opaque_App_Infos{
		info:      (*C.uchar)(C.CBytes(infos.Info)),
		info_len:  C.ulong(len(infos.Info)),
		einfo:     (*C.uchar)(C.CBytes(infos.Einfo)),
		einfo_len: C.ulong(len(infos.Einfo)),
	}

	cfg, err := createConfig(cfg_)
	if err != nil {
		return nil, nil, nil, ids, errors.New("bad cfg")
	}

	envU_len := C.opaque_envelope_len(&cfg, &idCC)

	if len(resp) < C.OPAQUE_SERVER_SESSION_LEN+int(envU_len) {
		return nil, nil, nil, ids, errors.New("invalid resp param")
	}

	pkS_ptr := (*C.uchar)(nil)
	if pkS != nil {
		if len(pkS) != C.crypto_scalarmult_BYTES {
			return nil, nil, nil, ids, errors.New("invalid pkS param")
		}
		if cfg_.PkS != CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("redundant pkS param")
		}
		pkS_ptr = (*C.uchar)(C.CBytes(pkS))
	} else {
		if cfg_.PkS == CfgNotPackaged {
			return nil, nil, nil, ids, errors.New("missing pkS param")
		}
	}

	sk := C.malloc(C.OPAQUE_SHARED_SECRETBYTES)
	if sk == nil {
		return nil, nil, nil, ids, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(sk))
	authU := C.malloc(C.crypto_auth_hmacsha256_BYTES)
	if authU == nil {
		return nil, nil, nil, ids, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(authU))
	export_key := C.malloc(C.crypto_hash_sha256_BYTES)
	if export_key == nil {
		return nil, nil, nil, ids, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(export_key))

	ret := C.opaque_RecoverCredentials(
		(*C.uchar)(C.CBytes(resp)),
		(*C.uchar)(C.CBytes(sec)),
		pkS_ptr,
		&cfg,
		&infoC,
		&idCC,
		(*C.uchar)(sk),
		(*C.uchar)(authU),
		(*C.uchar)(export_key),
	)
	if ret != 0 {
		return nil, nil, nil, ids, errors.New("recover creds failed")
	}

	if cfg_.IdU != CfgNotPackaged {
		ids.IdU = C.GoBytes(unsafe.Pointer(idCC.idU), (C.int)(idCC.idU_len))
	}
	if cfg_.IdS != CfgNotPackaged {
		ids.IdS = C.GoBytes(unsafe.Pointer(idCC.idS), (C.int)(idCC.idS_len))
	}

	s := C.GoBytes(sk, (C.int)(C.OPAQUE_SHARED_SECRETBYTES))
	a := C.GoBytes(authU, (C.crypto_auth_hmacsha256_BYTES))
	e := C.GoBytes(export_key, (C.crypto_hash_sha256_BYTES))
	return s, a, e, ids, nil
}

// This is a function not explicitly specified in the original paper. In the
// irtf cfrg draft authentication is done using a hmac of the session
// transcript with different keys coming out of a hkdf after the key
// exchange.
func UserAuth(sec []byte, authU []byte) error {
	// int opaque_UserAuth(
	// in
	//       const uint8_t sec[OPAQUE_SERVER_AUTH_CTX_LEN],
	//       const uint8_t authU[crypto_auth_hmacsha256_BYTES]);

	if len(sec) != C.OPAQUE_SERVER_AUTH_CTX_LEN {
		return errors.New("invalid sec param")
	}
	if len(authU) != C.crypto_auth_hmacsha256_BYTES {
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
// CreateRegReq() function, it outputs a value sec which needs to be
// protected until step 4 by the server. This function also outputs a
// value resp which needs to be passed to the user.
func CreateRegResp(req []byte, pkS []byte) ([]byte, []byte, error) {
	// int opaque_CreateRegistrationResponse(
	// in
	//        const uint8_t M[crypto_core_ristretto255_BYTES],
	// out
	//        uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	//        uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);
	// int opaque_Create1kRegistrationResponse(
	// in
	//        const uint8_t M[crypto_core_ristretto255_BYTES],
	//        const uint8_t pkS[crypto_scalarmult_BYTES],
	// out
	//        uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	//        uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

	if len(req) != C.crypto_core_ristretto255_BYTES {
		return nil, nil, errors.New("invalid req param")
	}
	if pkS != nil && len(pkS) != C.crypto_scalarmult_BYTES {
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
	if pkS == nil {
		ret = C.opaque_CreateRegistrationResponse(
			(*C.uchar)(C.CBytes(req)),
			(*C.uchar)(sec),
			(*C.uchar)(resp),
		)
	} else {
		ret = C.opaque_Create1kRegistrationResponse(
			(*C.uchar)(C.CBytes(req)),
			(*C.uchar)(C.CBytes(pkS)),
			(*C.uchar)(sec),
			(*C.uchar)(resp),
		)
	}
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
func FinalizeReq(sec []byte, resp []byte, cfg_ OpaqueCfg, ids OpaqueIDS) ([]byte, []byte, error) {
	// int opaque_FinalizeRequest(
	// in
	//       const uint8_t sec[OPAQUE_REGISTER_USER_SEC_LEN/*+pwdU_len*/],
	//       const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN],
	//       const Opaque_PkgConfig *cfg,
	//       const Opaque_Ids *ids,
	// out
	//       uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/],
	//       uint8_t export_key[crypto_hash_sha256_BYTES]);
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

	cfg, err := createConfig(cfg_)
	if err != nil {
		return nil, nil, errors.New("bad cfg")
	}

	envU_len := C.opaque_envelope_len(&cfg, &idCC)
	rec := C.malloc(C.OPAQUE_USER_RECORD_LEN + envU_len)
	if rec == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(rec))

	ek := C.malloc(C.crypto_hash_sha256_BYTES)
	if ek == nil {
		return nil, nil, errors.New("out of memory")
	}
	defer C.free(unsafe.Pointer(ek))

	ret := C.opaque_FinalizeRequest(
		(*C.uchar)(C.CBytes(sec)),
		(*C.uchar)(C.CBytes(resp)),
		&cfg,
		&idCC,
		(*C.uchar)(rec),
		(*C.uchar)(ek),
	)
	if ret != 0 {
		return nil, nil, errors.New("finalize req failed")
	}

	r := C.GoBytes(rec, (C.int)(C.OPAQUE_USER_RECORD_LEN+envU_len))
	e := C.GoBytes(ek, (C.crypto_hash_sha256_BYTES))
	return r, e, nil
}

// Final Registration step Global Server Key Version - server adds own
// info to the record to be stored.
//
// this function essentially does the same as StoreUserRec() except
// that it expects the server to provide its secret key. This server
// secret key might be one global secret key used for all users, or it
// might be a per-user unique key derived from a secret server seed.
//
// The rfc does not explicitly specify this function.  The server
// combines the sec value from its run of its CreateRegResp() function
// with the rec output of the users FinalizeReq() function, creating
// the final record, which should be the same as the output of the
// 1-step storePwdFile() init function of the paper. The server should
// save this record in combination with a user id and/or sid value as
// suggested in the paper.
func StoreUserRec(sec []byte, skS []byte, rec []byte) ([]byte, error) {
	// void opaque_StoreUserRecord(
	// in
	//       const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	// in/out
	//       uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);
	// void opaque_Store1kUserRecord(
	// in
	//       const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN],
	//       const uint8_t skS[crypto_scalarmult_SCALARBYTES],
	// in/out
	//       uint8_t rec[OPAQUE_USER_RECORD_LEN/*+envU_len*/]);

	if len(sec) != C.OPAQUE_REGISTER_SECRET_LEN {
		return nil, errors.New("invalid sec param")
	}

	if skS != nil && len(skS) != C.crypto_scalarmult_SCALARBYTES {
		return nil, errors.New("invalid skS param")
	}

	if len(rec) < C.OPAQUE_USER_RECORD_LEN {
		return nil, errors.New("invalid rec param")
	}

	trec := (*C.uchar)(C.CBytes(rec))
	if skS == nil {
		C.opaque_StoreUserRecord(
			(*C.uchar)(C.CBytes(sec)),
			trec,
		)
	} else {
		C.opaque_Store1kUserRecord(
			(*C.uchar)(C.CBytes(sec)),
			(*C.uchar)(C.CBytes(skS)),
			trec,
		)
	}

	rec = C.GoBytes(unsafe.Pointer(trec), (C.int)(len(rec)))
	return rec, nil
}
