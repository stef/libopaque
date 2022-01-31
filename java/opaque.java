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

    public OpaqueRecExpKey register(String pwd, byte[] skS, OpaqueIds ids) {
        return c_register(pwd, skS, ids);
    }
    public OpaqueRecExpKey register(String pwd, OpaqueIds ids) {
        return c_register(pwd, ids);
    }
    public OpaqueRecExpKey register(String pwd, byte[] skS) {
        return c_register(pwd, skS);
    }
    public OpaqueRecExpKey register(String pwd) {
        return c_register(pwd);
    }

    public OpaqueCredReq createCredReq(String pwd) {
        return c_createCredReq(pwd);
    }

    public OpaqueCredResp createCredResp(byte[] req, byte[] rec, OpaqueIds ids, String context) {
        return c_createCredResp(req, rec, ids, context);
    }

    public OpaqueCreds recoverCreds(byte[] resp, byte[] sec, String context, OpaqueIds ids) {
        return c_recoverCreds(resp, sec, context, ids);
    }

    public boolean userAuth(byte[] sec, byte[] authU) {
        return c_userAuth(sec, authU);
    }

    public OpaqueRegReq createRegReq(String pwd) {
        return c_createRegReq(pwd);
    }

    public OpaqueRegResp createRegResp(byte[] M, byte[] skS) {
        return c_createRegResp(M, skS);
    }

    public OpaqueRegResp createRegResp(byte[] M) {
        return c_createRegResp(M);
    }

    public OpaquePreRecExpKey finalizeReg(byte[] sec, byte[] pub, OpaqueIds ids) {
        return c_finalizeReg(sec, pub, ids);
    }

    public byte[] storeRec(byte[] sec, byte[] rec) {
        return c_storeRec(sec, rec);
    }

    private static native OpaqueRecExpKey c_register(String pwd, byte[] skS, OpaqueIds ids);
    private static native OpaqueRecExpKey c_register(String pwd, OpaqueIds ids);
    private static native OpaqueRecExpKey c_register(String pwd, byte[] skS);
    private static native OpaqueRecExpKey c_register(String pwd);
    private static native OpaqueCredReq c_createCredReq(String pwd);
    private static native OpaqueCredResp c_createCredResp(byte[] req, byte[] rec, OpaqueIds ids, String context);
    private static native OpaqueCreds c_recoverCreds(byte[] resp, byte[] sec, String context, OpaqueIds ids);
    private static native boolean c_userAuth(byte[] sec, byte[] authU);
    private static native OpaqueRegReq c_createRegReq(String pwd);
    private static native OpaqueRegResp c_createRegResp(byte[] M, byte[] skS);
    private static native OpaqueRegResp c_createRegResp(byte[] M);
    private static native OpaquePreRecExpKey c_finalizeReg(byte[] sec, byte[] pub, OpaqueIds ids);
    private static native byte[] c_storeRec(byte[] sec, byte[] rec);
}
