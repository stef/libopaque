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
$r=opaque_create_credential_request("simple guessable dictionary password");
echo bin2hex($r[0]), "\n";
echo bin2hex($r[1]), "\n";
?>
--EXPECT--
string(11) "Hello World"
