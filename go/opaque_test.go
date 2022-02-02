package libopaque

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func TestRegister(t *testing.T) {
	ids := OpaqueIDS{
		IdU: []byte("user"),
		IdS: []byte("server"),
	}

	context := "context"

	rec, ek, err := Register("asdf", nil, ids)
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

	resp, sk, ssec, err := CreateCredResp(pub, rec, ids, context)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, err := RecoverCred(resp, sec, context, ids)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\n", skU, authU, export_key)
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

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	context := "context"

	rec, ek, err := Register("asdf", skS, ids)
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

	resp, sk, ssec, err := CreateCredResp(pub, rec, ids, context)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, err := RecoverCred(resp, sec, context, ids)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\n", skU, authU, export_key)
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

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	recU, ek0, err := FinalizeReq(sec, resp, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("finalize req success\nrecU: %x\nek: %x\n", recU, ek0)
	}

	rec, err := StoreUserRec(ssec, recU)
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

	context := "context"

	resp, sk, ssec, err := CreateCredResp(pub, rec, ids, context)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, err := RecoverCred(resp, sec, context, ids)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek0, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\n", skU, authU, export_key)
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

	skS, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Error(err)
	}

	ssec, resp, err := CreateRegResp(req, skS)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("create reg resp success\n%x\n%x\n", ssec, resp)
	}

	ids := OpaqueIDS{
		IdS: []byte("server"),
		IdU: []byte("user"),
	}

	recU, ek0, err := FinalizeReq(sec, resp, ids)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("finalize req success\nrecU: %x\nek: %x\n", recU, ek0)
	}

	rec, err := StoreUserRec(ssec, recU)
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

	context := "context"

	resp, sk, ssec, err := CreateCredResp(pub, rec, ids, context)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Success\nresp: %x\nsk: %x\nsec: %x\n", resp, sk, ssec)
	}

	skU, authU, export_key, err := RecoverCred(resp, sec, context, ids)
	if err != nil {
		t.Error(err)
	} else {
		if !bytes.Equal(skU, sk) {
			t.Error(errors.New("sk doesn't match"))
		} else if !bytes.Equal(ek0, export_key) {
			t.Error(errors.New("export_key doesn't match"))
		} else {
			fmt.Printf("Success\nsk: %x\nauthU: %x\nexport_key: %x\n", skU, authU, export_key)
		}
	}

	err = UserAuth(ssec, authU)
	if err != nil {
		t.Error(err)
	} else {
		fmt.Printf("Auth Success\n")
	}
}
