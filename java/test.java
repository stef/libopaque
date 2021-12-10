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
        OpaqueConfig cfg = new OpaqueConfig(OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.InSecEnv);
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
		System.out.println("cfg.skU: " + cfg.skU + " ");
		System.out.println("cfg.pkU: " + cfg.pkU + " ");
		System.out.println("cfg.pkS: " + cfg.pkS + " ");
		System.out.println("cfg.idU: " + cfg.idU + " ");
		System.out.println("cfg.idS: " + cfg.idS + "\n");

        Opaque o = new Opaque();

        OpaqueRecExpKey ret = o.register("password", cfg, ids);
		System.out.println("rec=" + ret.rec + ", ek=" + ret.export_key);

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, ret.rec, cfg, ids);
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueIds ids0 = new OpaqueIds();
        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, cfg, ids0);

        String idU = new String(creds.ids.idU);
        String idS = new String(creds.ids.idS);
		System.out.println("idS: " + idS);
		System.out.println("idU: " + idU);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_noPks_noIds() {
        OpaqueConfig cfg = new OpaqueConfig(OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.NotPackaged);
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
		System.out.println("cfg.skU: " + cfg.skU + " ");
		System.out.println("cfg.pkU: " + cfg.pkU + " ");
		System.out.println("cfg.pkS: " + cfg.pkS + " ");
		System.out.println("cfg.idU: " + cfg.idU + " ");
		System.out.println("cfg.idS: " + cfg.idS + "\n");

        Opaque o = new Opaque();

        byte[] skS = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        OpaqueRecExpKey ret =o.register("password", skS, cfg, ids);
		System.out.println("rec=" + ret.rec + ", ek=" + ret.export_key);

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, ret.rec, cfg, ids);
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        byte[] pkS = fromHex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, pkS, cfg, ids);

        String idU = new String(creds.ids.idU);
        String idS = new String(creds.ids.idS);
		System.out.println("idS: " + idS);
		System.out.println("idU: " + idU);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_privreg() {
        Opaque o = new Opaque();
        OpaqueRegReq regReq = o.createRegReq("password");
        OpaqueRegResp regResp = o.createRegResp(regReq.M);

        OpaqueConfig cfg = new OpaqueConfig(OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.InSecEnv);
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
		System.out.println("cfg.skU: " + cfg.skU + " ");
		System.out.println("cfg.pkU: " + cfg.pkU + " ");
		System.out.println("cfg.pkS: " + cfg.pkS + " ");
		System.out.println("cfg.idU: " + cfg.idU + " ");
		System.out.println("cfg.idS: " + cfg.idS + "\n");

        OpaquePreRecExpKey prerec = o.finalizeReg(regReq.sec, regResp.pub, cfg, ids);

        byte[] rec = o.storeRec(regResp.sec, prerec.rec);
		System.out.println("rec: " + toHex(rec) + "\n");

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, rec, cfg, ids);
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, cfg, ids);

        String idU = new String(creds.ids.idU);
        String idS = new String(creds.ids.idS);
		System.out.println("idS: " + idS);
		System.out.println("idU: " + idU);

        assert o.userAuth(cresp.sec, creds.authU);
    }

    private static void test_priv1kreg() {
        Opaque o = new Opaque();
        OpaqueRegReq regReq = o.createRegReq("password");
        byte[] pkS = fromHex("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
        OpaqueRegResp regResp = o.createRegResp(regReq.M, pkS);

        OpaqueConfig cfg = new OpaqueConfig(OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.NotPackaged,
                                            OpaqueConfig.PkgTarget.InSecEnv,
                                            OpaqueConfig.PkgTarget.InSecEnv);
        OpaqueIds ids = new OpaqueIds("idU".getBytes(Charset.forName("UTF-8")),
                                      "idS".getBytes(Charset.forName("UTF-8")));
		System.out.println("cfg.skU: " + cfg.skU + " ");
		System.out.println("cfg.pkU: " + cfg.pkU + " ");
		System.out.println("cfg.pkS: " + cfg.pkS + " ");
		System.out.println("cfg.idU: " + cfg.idU + " ");
		System.out.println("cfg.idS: " + cfg.idS + "\n");
        OpaquePreRecExpKey prerec = o.finalizeReg(regReq.sec, regResp.pub, cfg, ids);

        byte[] skS = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] rec = o.storeRec(regResp.sec, skS, prerec.rec);
		System.out.println("rec: " + toHex(rec) + "\n");

        OpaqueCredReq creq = o.createCredReq("password");
		System.out.println("sec=" + creq.sec + ", pub=" + creq.pub);

        OpaqueCredResp cresp = o.createCredResp(creq.pub, rec, cfg, ids);
		System.out.println("sec=" + cresp.sec + ", pub=" + cresp.pub);

        OpaqueCreds creds = o.recoverCreds(cresp.pub, creq.sec, pkS, cfg, ids);

        String idU = new String(creds.ids.idU);
        String idS = new String(creds.ids.idS);
		System.out.println("idS: " + idS);
		System.out.println("idU: " + idU);

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
