import java.nio.charset.*;

class Main {
	public static void main(String args[]) {
        test1();
        test_noPks_noIds();
        test_privreg();
        test_priv1kreg();
		System.out.println("everything ok");
	}

    private static void test1() {
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
        Opaque o = new Opaque();

        OpaqueRecExpKey ret = o.register("password", ids);
		System.out.println("rec=" + ret.rec + ", ek=" + ret.export_key);

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, ret.rec, ids, "context");
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, "context", ids);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_noPks_noIds() {
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
        Opaque o = new Opaque();
        byte[] skS = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        OpaqueRecExpKey ret =o.register("password", skS, ids);
		System.out.println("rec=" + ret.rec + ", ek=" + ret.export_key);

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, ret.rec, ids, "context");
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, "context", ids);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_privreg() {
        Opaque o = new Opaque();
        OpaqueRegReq regReq = o.createRegReq("password");
        OpaqueRegResp regResp = o.createRegResp(regReq.M);

        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
        OpaquePreRecExpKey prerec = o.finalizeReg(regReq.sec, regResp.pub, ids);

        byte[] rec = o.storeRec(regResp.sec, prerec.rec);
		System.out.println("rec: " + toHex(rec) + "\n");

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, rec, ids, "context");
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, "context", ids);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_priv1kreg() {
        Opaque o = new Opaque();
        OpaqueRegReq regReq = o.createRegReq("password");
        byte[] skS = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        OpaqueRegResp regResp = o.createRegResp(regReq.M, skS);

        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));

        OpaquePreRecExpKey prerec = o.finalizeReg(regReq.sec, regResp.pub, ids);

        byte[] rec = o.storeRec(regResp.sec, prerec.rec);
		System.out.println("rec: " + toHex(rec) + "\n");

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, rec, ids, "context");
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, "context", ids);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    // stackoverflowd from https://stackoverflow.com/a/140861
    public static byte[] fromHex(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // strackoverflowed from: https://stackoverflow.com/a/9855338
    private static final byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    public static String toHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }
}
