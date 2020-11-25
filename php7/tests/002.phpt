--TEST--
opaque_test2() Basic test
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$r=opaque_register("simple guessable dictionary password", "user", "server", [opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv, opaque_InSecEnv], "some optional key contributed to the opaque protocol");
echo bin2hex($r[0]), "\n";
echo bin2hex($r[1]), "\n";
?>
--EXPECT--
string(11) "Hello World"
