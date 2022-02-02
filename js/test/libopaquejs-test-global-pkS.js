#!/usr/bin/env node

"use strict";

const opaque = require("../dist/libopaque.debug.js");

(async () => {
  await opaque.ready;

  const pwdU = "simple guessable dictionary password";
  const ids = { idU: "user", idS: "server" };
  const context = "context";
  const { pkS, skS } = opaque.genServerKeyPair();

  let { sec: secU, M } = opaque.createRegistrationRequest({ pwdU });
  let { sec: secS, pub } = opaque.createRegistrationResponse({ M, skS });
  let { rec, export_key } = opaque.finalizeRequest({
    sec: secU,
    pub,
    ids,
  });
  ({ rec } = opaque.storeUserRecord({ sec: secS, rec }));
  ({ sec: secU, pub } = opaque.createCredentialRequest({ pwdU }));
  let resp, sk;
  ({ resp, sk, sec: secS } = opaque.createCredentialResponse({
    pub,
    rec,
    ids,
    context
  }));
  const {
    sk: sk1,
    authU,
    export_key: export_key1,
  } = opaque.recoverCredentials({
    resp,
    sec: secU,
    context,
    ids,
  });
  if (!opaque.userAuth({ sec: secS, authU }))
    throw new Error("userAuth failed!");
  if (!opaque.uint8ArrayEquals(export_key, export_key1))
    throw new Error("export_key must equal export_key1.");
  if (!opaque.uint8ArrayEquals(sk, sk1)) throw new Error("sk must equal sk1.");
  console.error("Success!");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
