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

type OpaqueInfos struct {
	Info  []byte
	Einfo []byte
}

type OpaqueIDS struct {
	IdU []byte
	IdS []byte
}

type OpaqueCfg struct {
	SkU C.int
	PkU C.int
	PkS C.int
	IdU C.int
	IdS C.int
}

const (
	CfgNotPackaged C.int = C.NotPackaged
	CfgInSecEnv    C.int = C.InSecEnv
	CfgInClrEnv    C.int = C.InClrEnv
)

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
	//fmt.Printf("> idCC.idU(%d): %s\n", C.int(idCC.idS_len),
	//	C.GoBytes(unsafe.Pointer(idCC.idS), (C.int)(idCC.idS_len)))
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
