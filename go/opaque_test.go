package libopaque

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestRegister(t *testing.T) {
	cfg := OpaqueCfg{
		SkU: CfgInSecEnv,
		PkU: CfgNotPackaged,
		PkS: CfgInClrEnv,
		IdU: CfgInClrEnv,
		IdS: CfgInSecEnv,
	}

	ids := OpaqueIDS{
		IdU: []byte("user"),
		IdS: []byte("server"),
	}

	infos := OpaqueInfos{
		Info:  []byte("info"),
		Einfo: []byte("einfo"),
	}

	rec, ek, err := Register("asdf", nil, cfg, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("register success\n%x\n%x\n", rec, ek)
	}

	sec, pub, err := CreateCredReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nsec: %x\npub: %x\n", sec, pub)
	}

	resp, sk, ssec, err := CreateCredResp(pub, rec, cfg, ids, infos)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, ids1, err := RecoverCred(resp, sec, nil, cfg, OpaqueIDS{}, infos)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\nids: %x\n", skU, authU, export_key, ids1)
		}
	}

	err = UserAuth(ssec, authU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Auth Success\n")
	}
}

func TestRegisterSks(t *testing.T) {
	skS, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Error(err)
	}
	cfg := OpaqueCfg{
		SkU: CfgInSecEnv,
		PkU: CfgNotPackaged,
		PkS: CfgNotPackaged,
		IdU: CfgInSecEnv,
		IdS: CfgInClrEnv,
	}

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	infos := OpaqueInfos{
		Info:  []byte("info"),
		Einfo: []byte("einfo"),
	}

	rec, ek, err := Register("asdf", skS, cfg, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nrec: %x\nek: %x\n", rec, ek)
	}

	sec, pub, err := CreateCredReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nsec: %x\npub: %x\n", sec, pub)
	}

	resp, sk, ssec, err := CreateCredResp(pub, rec, cfg, ids, infos)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	pkS, err := hex.DecodeString("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
	if err != nil {
		t.Error(err)
	}
	skU, authU, export_key, ids1, err := RecoverCred(resp, sec, pkS, cfg, OpaqueIDS{}, infos)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\nids: %x\n", skU, authU, export_key, ids1)
		}
	}

	err = UserAuth(ssec, authU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Auth Success\n")
	}
}

func TestRegDance(t *testing.T) {
	sec, req, err := CreateRegReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("create reg req success\n%x\n%x\n", sec, req)
	}

	ssec, resp, err := CreateRegResp(req, nil)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("create reg resp success\n%x\n%x\n", ssec, resp)
	}

	cfg := OpaqueCfg{
		SkU: CfgInSecEnv,
		PkU: CfgNotPackaged,
		PkS: CfgInClrEnv,
		IdU: CfgInSecEnv,
		IdS: CfgInClrEnv,
	}

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	recU, ek0, err := FinalizeReq(sec, resp, cfg, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("finalize req success\nrecU: %x\nek: %x\n", recU, ek0)
	}

	rec, err := StoreUserRec(ssec, nil, recU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("store user rec success\nrec: %x\n", rec)
	}

	sec, pub, err := CreateCredReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nsec: %x\npub: %x\n", sec, pub)
	}

	infos := OpaqueInfos{
		Info:  []byte("info"),
		Einfo: []byte("einfo"),
	}

	resp, sk, ssec, err := CreateCredResp(pub, rec, cfg, ids, infos)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, ids1, err := RecoverCred(resp, sec, nil, cfg, OpaqueIDS{}, infos)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek0, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\nids: %x\n", skU, authU, export_key, ids1)
		}
	}

	err = UserAuth(ssec, authU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Auth Success\n")
	}
}

func TestRegDance1k(t *testing.T) {
	sec, req, err := CreateRegReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("create reg req success\n%x\n%x\n", sec, req)
	}

	pkS, err := hex.DecodeString("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")
	if err != nil {
		t.Error(err)
	}

	ssec, resp, err := CreateRegResp(req, pkS)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("create reg resp success\n%x\n%x\n", ssec, resp)
	}

	cfg := OpaqueCfg{
		SkU: CfgInSecEnv,
		PkU: CfgNotPackaged,
		PkS: CfgNotPackaged,
		IdU: CfgInSecEnv,
		IdS: CfgInClrEnv,
	}

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	recU, ek0, err := FinalizeReq(sec, resp, cfg, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("finalize req success\nrecU: %x\nek: %x\n", recU, ek0)
	}

	skS, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Error(err)
	}
	rec, err := StoreUserRec(ssec, skS, recU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("store user rec success\nrec: %x\n", rec)
	}

	sec, pub, err := CreateCredReq("asdf")
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nsec: %x\npub: %x\n", sec, pub)
	}

	infos := OpaqueInfos{
		Info:  []byte("info"),
		Einfo: []byte("einfo"),
	}

	resp, sk, ssec, err := CreateCredResp(pub, rec, cfg, ids, infos)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, ids1, err := RecoverCred(resp, sec, pkS, cfg, OpaqueIDS{}, infos)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek0, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\nids: %x\n", skU, authU, export_key, ids1)
		}
	}

	err = UserAuth(ssec, authU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Auth Success\n")
	}
}
