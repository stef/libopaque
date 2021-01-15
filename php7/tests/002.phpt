--TEST--
opaque_test6() Basic test
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
$exp_key0 = $r[1];
$r=opaque_create_credential_request("simple guessable dictionary password");
$sec = $r[0];
$pub = $r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", $cfg);
$resp=$r[0];
$sk=$r[1];
$ctx=$r[2];
$r=opaque_recover_credentials($resp, $sec, $cfg);
$sk=$r[0];
$authU=$r[1];
$export_key=$r[2];
$idU=$r[3];
$idS=$r[4];
var_dump(opaque_user_auth($ctx, $authU));
?>
--EXPECT--
bool(true)
