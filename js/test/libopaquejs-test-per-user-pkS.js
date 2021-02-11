#!/usr/bin/env node

"use strict";

const opaque = require("../dist/libopaque.js");

(async () => {
  await opaque.ready;

  const pwdU = "simple guessable dictionary password";
  const cfg = {
    skU: opaque.NotPackaged,
    pkU: opaque.NotPackaged,
    pkS: opaque.InSecEnv,
    idS: opaque.NotPackaged,
    idU: opaque.NotPackaged,
  };
  const ids = { idU: "user", idS: "server" };
  const infos = null;

  let { sec: secU, M } = opaque.createRegistrationRequest({ pwdU });
  let { sec: secS, pub } = opaque.createRegistrationResponse({ M });
  let { rec, export_key } = opaque.finalizeRequest({
    sec: secU,
    pub,
    cfg,
    ids,
  });
  ({ rec } = opaque.storeUserRecord({ sec: secS, rec }));
  ({ sec: secU, pub } = opaque.createCredentialRequest({ pwdU }));
  let resp, sk;
  ({ resp, sk, sec: secS } = opaque.createCredentialResponse({
    pub,
    rec,
    cfg,
    ids,
    infos,
  }));
  const {
    ids: ids1,
    sk: sk1,
    authU,
    export_key: export_key1,
  } = opaque.recoverCredentials({
    resp,
    sec: secU,
    pkS: null,
    cfg,
    infos,
    ids,
  });
  if (!opaque.userAuth({ sec: secS, authU }))
    throw new Error("userAuth failed!");
  if (ids.idU !== ids1.idU)
    throw new Error(
      "The recovered user ID (ids1.idU) must equal the registration user ID (ids.idU)."
    );
  if (ids.idS !== ids1.idS)
    throw new Error(
      "The recovered server ID (ids1.idS) must equal the registration server ID (ids.idS)."
    );
  if (!opaque.uint8ArrayEquals(export_key, export_key1))
    throw new Error("export_key must equal export_key1.");
  if (!opaque.uint8ArrayEquals(sk, sk1)) throw new Error("sk must equal sk1.");
  console.error("Success!");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
