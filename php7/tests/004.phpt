--TEST--
opaque_test4() Registration with Global Server Keys
--SKIPIF--
<?php
if (!extension_loaded('opaque')) {
	echo 'skip';
}
?>
--FILE--
<?php
$r=opaque_create_server_keys();
$pkS=$r[0];
$skS=$r[1];
$r=opaque_create_registration_request("simple guessable dictionary password");
$M=$r[0];
$secU=$r[1];
$r=opaque_create_1k_registration_response($M, $pkS);
$secS=$r[0];
$pub=$r[1];
$cfg=[opaque_NotPackaged, opaque_NotPackaged, opaque_NotPackaged, opaque_NotPackaged, opaque_NotPackaged];
$r=opaque_finalize_request($secU, $pub, "user", "server", $cfg);
$rec=$r[0];
$export_key=$r[1];
$rec=opaque_store_1k_user_record($secS, $skS, $rec);
$r=opaque_create_credential_request("simple guessable dictionary password");
$secU=$r[0];
$pub=$r[1];
$r=opaque_create_credential_response($pub, $rec, "user", "server", $cfg);
$resp=$r[0];
$sk=$r[1];
$secS=$r[2];
$r=opaque_recover_credentials($resp, $secU, $cfg, array(), $pkS, "user", "server");
$sk1=$r[0];
$authU=$r[1];
$export_key1=$r[2];
$idU=$r[3];
$idS=$r[4];
assert("user" == $idU);
assert("server" == $idS);
assert($export_key == $export_key1);
assert($sk == $sk1);
var_dump(opaque_user_auth($secS, $authU));
?>
--EXPECT--
bool(true)
