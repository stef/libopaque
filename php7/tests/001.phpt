--TEST--
Check if opaque is loaded
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "opaque" is available';
?>
--EXPECT--
The extension "opaque" is available
