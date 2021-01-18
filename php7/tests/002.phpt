--TEST--
opaque_test2() One-step Registration
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$cfg=[opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv];
$r=opaque_register("simple guessable dictionary password", "user", "server", $cfg);
$rec = $r[0];
$export_key= $r[1];
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
