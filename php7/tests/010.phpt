--TEST--
opaque_test10() Basic test
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
$cfg = [opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv];
$r=opaque_finalize_request($ctx, $rpub, "user", "server", $cfg, "some optional key contributed to the opaque protocol");
$rrec = $r[0];
$export_key = $r[1];
$rec = opaque_store_user_record($rsec, $rrec);
echo "record: ", bin2hex($rec), "\n";
?>
--EXPECT--
string(11) "Hello World"
