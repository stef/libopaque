--TEST--
opaque_test3() Basic test
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$r=opaque_create_registration_request("simple guessable dictionary password");
$M = $r[0];
$secU = $r[1];
$r=opaque_create_registration_response($M);
$secS = $r[0];
$pub = $r[1];
$cfg = [opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv];
$r=opaque_finalize_request($secU, $pub, "user", "server", $cfg);
$rec = $r[0];
$export_key = $r[1];
$rec = opaque_store_user_record($secS, $rec);
$r=opaque_create_credential_request("simple guessable dictionary password");
$secU = $r[0];
$pub = $r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", $cfg);
$resp=$r[0];
$sk=$r[1];
$secS=$r[2];
$r=opaque_recover_credentials($resp, $secU, $cfg);
$sk1=$r[0];
$authU=$r[1];
$export_key1=$r[2];
$idU=$r[3];
$idS=$r[4];
assert("user" == $idU);
assert("server" == $idS);
assert($export_key == $export_key1);
assert($sk == $sk1);
var_dump(opaque_user_auth($secS, $authU));
?>
--EXPECT--
bool(true)
