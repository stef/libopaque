--TEST--
opaque_test8() Basic test
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
?>
--EXPECT--
string(11) "Hello World"
