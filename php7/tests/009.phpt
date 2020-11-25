--TEST--
opaque_test9() Basic test
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
?>
--EXPECT--
string(11) "Hello World"
