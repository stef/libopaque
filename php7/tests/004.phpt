--TEST--
opaque_test4() Basic test
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$r=opaque_register("simple guessable dictionary password", "user", "server", [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv], "some optional key contributed to the opaque protocol");
$rec = $r[0];
#exp_key0 = $r[1];
$r=opaque_create_credential_request("simple guessable dictionary password");
$sec = $r[0];
$pub = $r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", [InSecEnv, InSecEnv, InSecEnv, InSecEnv, InSecEnv]);
$resp=$r[0];
$sk=$r[1];
$ctx=$r[2];
echo "resp: ", bin2hex($resp), "\n";
echo "sk: ", bin2hex($sk), "\n";
echo "ctx: ", bin2hex($ctx), "\n";
?>
--EXPECT--
string(11) "Hello World"
