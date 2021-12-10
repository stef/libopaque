class OpaqueConfig {
    public enum PkgTarget {
        NotPackaged,
        InSecEnv,
        InClrEnv
    }
    public PkgTarget skU;
    public PkgTarget pkU;
    public PkgTarget pkS;
    public PkgTarget idU;
    public PkgTarget idS;

    public OpaqueConfig(PkgTarget _skU, PkgTarget _pkU, PkgTarget _pkS, PkgTarget _idU, PkgTarget _idS) {
        skU = _skU;
        pkU = _pkU;
        pkS = _pkS;
        idU = _idU;
        idS = _idS;
    }
}

class OpaqueIds {
    public OpaqueIds() {}
    public OpaqueIds(byte[] idU_, byte[] idS_) {
        idU = idU_;
        idS = idS_;
    }

    public byte[] idU;
    public byte[] idS;
}

class OpaqueRecExpKey {
    public byte[] rec;
    public byte[] export_key;
}

class OpaqueCredReq {
    public byte[] sec;
    public byte[] pub;
}

class OpaqueCredResp {
    public byte[] sec;
    public byte[] sk;
    public byte[] pub;
}

class OpaqueCreds {
    public OpaqueIds ids;
    public byte[] sk;
    public byte[] authU;
    public byte[] export_key;
}

class OpaqueRegReq {
    public byte[] sec;
    public byte[] M;
}

class OpaqueRegResp {
    public byte[] sec;
    public byte[] pub;
}

class OpaquePreRecExpKey {
    public byte[] rec;
    public byte[] export_key;
}

class Opaque {
    static {
        System.loadLibrary("opaquejni");
    }

    public OpaqueRecExpKey register(String pwd, byte[] skS, OpaqueConfig cfg, OpaqueIds ids) {
        return c_register(pwd, skS, cfg, ids);
    }
    public OpaqueRecExpKey register(String pwd, OpaqueConfig cfg, OpaqueIds ids) {
        return c_register(pwd, cfg, ids);
    }

    public OpaqueCredReq createCredReq(String pwd) {
        return c_createCredReq(pwd);
    }

    public OpaqueCredResp createCredResp(byte[] req, byte[] rec, OpaqueConfig cfg, OpaqueIds ids) {
        return c_createCredResp(req, rec, cfg, ids);
    }

    public OpaqueCreds recoverCreds(byte[] resp, byte[] sec, byte[] pkS, OpaqueConfig cfg, OpaqueIds ids) {
        return c_recoverCreds(resp, sec, pkS, cfg, ids);
    }

    public OpaqueCreds recoverCreds(byte[] resp, byte[] sec, OpaqueConfig cfg, OpaqueIds ids) {
        return c_recoverCreds(resp, sec, cfg, ids);
    }

    public boolean userAuth(byte[] sec, byte[] authU) {
        return c_userAuth(sec, authU);
    }

    public OpaqueRegReq createRegReq(String pwd) {
        return c_createRegReq(pwd);
    }

    public OpaqueRegResp createRegResp(byte[] M) {
        return c_createRegResp(M);
    }

    public OpaqueRegResp createRegResp(byte[] M, byte[] pkS) {
        return c_createRegResp(M, pkS);
    }

    public OpaquePreRecExpKey finalizeReg(byte[] sec, byte[] pub, OpaqueConfig cfg, OpaqueIds ids) {
        return c_finalizeReg(sec, pub, cfg, ids);
    }

    public byte[] storeRec(byte[] sec, byte[] rec) {
        return c_storeRec(sec, rec);
    }

    public byte[] storeRec(byte[] sec, byte[] skS, byte[] rec) {
        return c_storeRec(sec, skS, rec);
    }

    private static native OpaqueRecExpKey c_register(String pwd, byte[] skS, OpaqueConfig cfg, OpaqueIds ids);
    private static native OpaqueRecExpKey c_register(String pwd, OpaqueConfig cfg, OpaqueIds ids);
    private static native OpaqueCredReq c_createCredReq(String pwd);
    private static native OpaqueCredResp c_createCredResp(byte[] req, byte[] rec, OpaqueConfig cfg, OpaqueIds ids);
    private static native OpaqueCreds c_recoverCreds(byte[] resp, byte[] sec, byte[] pkS, OpaqueConfig cfg, OpaqueIds ids);
    private static native OpaqueCreds c_recoverCreds(byte[] resp, byte[] sec, OpaqueConfig cfg, OpaqueIds ids);
    private static native boolean c_userAuth(byte[] sec, byte[] authU);
    private static native OpaqueRegReq c_createRegReq(String pwd);
    private static native OpaqueRegResp c_createRegResp(byte[] M);
    private static native OpaqueRegResp c_createRegResp(byte[] M, byte[] pkS);
    private static native OpaquePreRecExpKey c_finalizeReg(byte[] sec, byte[] pub, OpaqueConfig cfg, OpaqueIds ids);
    private static native byte[] c_storeRec(byte[] sec, byte[] rec);
    private static native byte[] c_storeRec(byte[] sec, byte[] skS, byte[] rec);
}
