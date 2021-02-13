"use strict";

// https://expressjs.com/en/starter/hello-world.html
const express = require("express");
const opaque = require("../dist/libopaque.js");
const path = require("path");
const rateLimit = require("express-rate-limit");

const app = express();
const port = 8080;

const users = {};
const credentialSecrets = {};
const registerSecrets = {};

(async () => {
  await opaque.ready;

  const cfg = {
    skU: opaque.NotPackaged,
    pkU: opaque.NotPackaged,
    pkS: opaque.InSecEnv,
    idS: opaque.NotPackaged,
    idU: opaque.NotPackaged,
  };
  const idS = "server";
  const infos = {
    info: null,
    einfo: null,
  };
  const pkS = opaque.hexToUint8Array(
    "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
  );
  const skS = opaque.hexToUint8Array(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  );

  // https://expressjs.com/en/starter/static-files.html
  app.use(express.static(path.join(__dirname, "public")));

  // https://expressjs.com/en/api.html#express.urlencoded
  // https://stackoverflow.com/questions/4295782/how-to-process-post-data-in-node-js
  // https://stackoverflow.com/questions/25471856/express-throws-error-as-body-parser-deprecated-undefined-extended
  app.use(express.urlencoded({ extended: true }));

  // Auth0 has a user/password authentication rate limit of 20 per minute:
  // https://web.archive.org/web/20201111055850/https://auth0.com/docs/policies/rate-limit-policy/database-connections-rate-limits.
  // Since the OPAQUE protocol requires some back and forth (e.g., registration
  // takes at least 3 requests), let's set the limit to 100 requests per minute.
  // Having a rate limiter fixes the following CodeQL finding:
  // https://web.archive.org/web/20210213102815/https://github.com/github/codeql/blob/main/javascript/ql/src/Security/CWE-770/MissingRateLimiting.ql.
  const limiter = rateLimit({
    windowMs: 60 * 1000, // = 1 minute.
    max: 100, // Limit each IP to 100 requests per windowMs.
  });
  app.use(limiter);

  app.post("/register-with-password", (req, res) => {
    try {
      console.log(req.body);
      const pwdU = req.body.pw;
      const skS = null;
      const idU = req.body.id;
      // registration = { rec, export_key }
      const registration = opaque.register({
        pwdU,
        skS,
        cfg,
        ids: { idS, idU },
      });
      // Allow registration to go through to prevent user-enumeration attacks.
      if (!users[idU]) users[idU] = registration;
      // else The user is already registered.
      res.json({});
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/request-credentials", (req, res) => {
    try {
      console.log(req.body);
      const pub = opaque.hexToUint8Array(req.body.request);
      const idU = req.body.id;

      const rec = users[idU] ? users[idU].rec : null;
      if (!rec) {
        res.json({ error: "Requesting credentials for the user failed." });
        return;
      }

      const { resp, sk, sec } = opaque.createCredentialResponse({
        pub,
        rec,
        cfg,
        ids: { idS, idU },
        infos,
      });
      credentialSecrets[idU] = sec;

      const response = { response: opaque.uint8ArrayToHex(resp) };
      if (cfg.pkS === opaque.NotPackaged) {
        const { pkS: _pkS } = opaque.getServerPublicKeyFromUserRecord({ rec });
        response.pkS = opaque.uint8ArrayToHex(_pkS);
      }
      res.json(response);
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/authorize", (req, res) => {
    try {
      console.log(req.body);
      const sec = credentialSecrets[req.body.id];
      delete credentialSecrets[req.body.id];
      const authU = opaque.hexToUint8Array(req.body.auth);
      res.json(
        opaque.userAuth({
          sec,
          authU,
        })
      );
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/register-without-password", (req, res) => {
    try {
      console.log(req.body);
      const idU = req.body.id;
      const request = opaque.hexToUint8Array(req.body.request);
      const response = opaque.createRegistrationResponse({ M: request });
      registerSecrets[idU] = response.sec;
      res.json({ response: opaque.uint8ArrayToHex(response.pub) });
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/store-user-record", (req, res) => {
    try {
      console.log(req.body);
      const idU = req.body.id;
      const sec = registerSecrets[idU];
      delete registerSecrets[idU];
      const rec = opaque.hexToUint8Array(req.body.rec);
      const userRec = opaque.storeUserRecord({ sec, rec });
      // Allow registration to go through to prevent user-enumeration attacks.
      if (!users[idU]) users[idU] = userRec;
      // else The user is already registered.
      res.json(true);
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/register-with-global-server-key", (req, res) => {
    try {
      console.log(req.body);
      const idU = req.body.id;
      const request = opaque.hexToUint8Array(req.body.request);
      const response = opaque.create1kRegistrationResponse({
        M: request,
        pkS,
      });
      registerSecrets[idU] = response.sec;
      res.json({
        response: opaque.uint8ArrayToHex(response.pub),
        type: "global-server-key",
      });
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.post("/store-user-record-using-global-server-key", (req, res) => {
    try {
      console.log(req.body);
      const idU = req.body.id;
      const sec = registerSecrets[idU];
      delete registerSecrets[idU];
      const rec = opaque.hexToUint8Array(req.body.rec);
      const userRec = opaque.store1kUserRecord({
        sec,
        skS,
        rec,
      });
      // Allow registration to go through to prevent user-enumeration attacks.
      if (!users[idU]) users[idU] = userRec;
      // else The user is already registered.
      res.json(true);
    } catch (e) {
      console.error(e);
      res.json({ error: e.message });
    }
  });

  app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
  });
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
