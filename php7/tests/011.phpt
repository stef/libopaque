--TEST--
opaque_test11() Basic test
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$r=opaque_create_registration_request("simple guessable dictionary password");
$alpha = $r[0];
$ctx = $r[1];
$r=opaque_create_registration_response($alpha);
$rsec = $r[0];
$rpub = $r[1];
$r=opaque_finalize_request($ctx, $rpub, "user", "server", [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv], "some optional key contributed to the opaque protocol");
$rrec = $r[0];
$export_key = $r[1];
$rec = opaque_store_user_record($rsec, $rrec);
echo "record: ", bin2hex($rec), "\n";
$r=opaque_create_credential_request("simple guessable dictionary password");
$sec = $r[0];
$pub = $r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv]);
$resp=$r[0];
$sk=$r[1];
$ctx=$r[2];
$r=opaque_recover_credentials($resp, $sec, [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv], "some optional key contributed to the opaque protocol");
$sk=$r[0];
$authU=$r[1];
$export_key=$r[2];
$idU=$r[3];
$idS=$r[4];
var_dump(opaque_user_auth($ctx, $authU));
?>
--EXPECT--
string(11) "Hello World"
