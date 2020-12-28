--TEST--
opaque_test5() Basic test
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$cfg=[opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv];
$r=opaque_register("simple guessable dictionary password", "user", "server", $cfg, "some optional key contributed to the opaque protocol");
$rec = $r[0];
#exp_key0 = $r[1];
$r=opaque_create_credential_request("simple guessable dictionary password");
$sec = $r[0];
$pub = $r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", $cfg);
$resp=$r[0];
$sk=$r[1];
$ctx=$r[2];
$r=opaque_recover_credentials($resp, $sec, $cfg, "some optional key contributed to the opaque protocol");
$sk=$r[0];
$authU=$r[1];
$export_key=$r[2];
$idU=$r[3];
$idS=$r[4];
echo "sk: ", bin2hex($sk), "\n";
echo "authU: ", bin2hex($authU), "\n";
echo "export_key: ", bin2hex($export_key), "\n";
echo "idU: ", bin2hex($idU), "\n";
echo "idS: ", bin2hex($idS), "\n";
?>
--EXPECT--
string(11) "Hello World"