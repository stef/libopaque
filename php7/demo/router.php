<?php

$cfg = [opaque_NotPackaged, opaque_NotPackaged, opaque_InSecEnv, opaque_NotPackaged, opaque_NotPackaged];
$idS = "server";
$pkS = hex2bin("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f");
$skS = hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

function opaque_apcu_fetch($domain, $idU) {
  $value = apcu_fetch($domain . '_' . $idU);
  // error_log('fetch: ' . $domain . '_' . $idU . ' = ' . $value);
  // if ($value === false)
  //   error_log("Fetching " . $domain . '_' . $idU . " failed.");
  return (isset($value) && !empty($value)) ? $value : null;
}

function opaque_apcu_store($domain, $idU, $value) {
  // error_log('store: ' . $domain . '_' . $idU . ' = ' . $value);
  if (apcu_store($domain . '_' . $idU, $value) === false)
    error_log("Storing " . $domain . '_' . $idU . " failed.");
}

function opaque_fetch($domain, $idU) {
  return opaque_apcu_fetch($domain, $idU);
}

function opaque_store($domain, $idU, $value) {
  opaque_apcu_store($domain, $idU, $value);
}

error_log($_SERVER["REQUEST_URI"]);

switch ($_SERVER["REQUEST_URI"]) {

    case "/info":
        phpinfo();
        break;

    case "/register-with-password":
        try {
          header('Content-Type: application/json');
          $pwdU = $_POST["pw"];
          $idU = $_POST["id"];
          $r = opaque_register($pwdU, $idU, $idS, $cfg);
          $rec = $r[0];
          $export_key = $r[1];
          $user = opaque_fetch("users", $idU);
          $hex = bin2hex($rec);
          if (!empty($hex)) {
            if ($user === null) {
              opaque_store("users", $idU, $hex);
            } else {
              // We allow registration to go through to prevent user-enumeration attacks.
              opaque_store("dummy", "", $hex);
            }
          }
          echo json_encode((object)[]);
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/request-credentials":
        try {
          header('Content-Type: application/json');
          $pub = hex2bin($_POST["request"]);
          $idU = $_POST["id"];
          $rec = hex2bin(opaque_fetch("users", $idU));
          if (!isset($rec)) {
            // TODO Prevent user enumeration attacks.
            $json_obj = (object)[];
            $json_obj->error = "Requesting credentials for the user failed.";
            echo json_encode($json_obj);
          } else {
            $r=opaque_create_credential_response($pub, $rec, $idU, $idS, $cfg);
            if (is_null($r)) {
              $json_obj = (object)[];
              $json_obj->error = "Requesting credentials for the user failed.";
              echo json_encode($json_obj);
              break;
            }
            $resp=$r[0];
            $sk=$r[1];
            $secS=$r[2];
            opaque_store("credential", $idU, bin2hex($secS));
            // error_log(bin2hex($secS));
            $json_obj = (object)[];
            $json_obj->response = bin2hex($resp);
            // TODO Handle pkS not packaged.
            echo json_encode($json_obj);
          }
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/authorize":
        try {
          header('Content-Type: application/json');
          $idU = $_POST["id"];
          $secS = hex2bin(opaque_fetch("credential", $idU));
          // error_log(bin2hex($secS));
          $authU = hex2bin($_POST["auth"]);
          echo opaque_user_auth($secS, $authU) ? "true" : "false";
          opaque_store("credential", $idU, null);
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/register-without-password":
        try {
          header('Content-Type: application/json');
          $idU = $_POST["id"];
          $M = hex2bin($_POST["request"]);
          $r = opaque_create_registration_response($M);
          $secS = $r[0];
          $pub = $r[1];
          $json_obj = (object)[];
          $json_obj->response = bin2hex($pub);
          echo json_encode($json_obj);
          opaque_store("registration", $idU, bin2hex($secS));
          // error_log(bin2hex($secS));
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/store-user-record":
        try {
          header('Content-Type: application/json');
          $idU = $_POST["id"];
          $rec = hex2bin($_POST["rec"]);
          $secS = hex2bin(opaque_fetch("registration", $idU));
          // error_log(bin2hex($secS));
          $rec = opaque_store_user_record($secS, $rec);
          $user = opaque_fetch("users", $idU);
          $hex = bin2hex($rec);
          if (!empty($hex)) {
            if ($user === null) {
              opaque_store("users", $idU, $hex);
            } else {
              // We allow registration to go through to prevent user-enumeration attacks.
              opaque_store("dummy", "", $hex);
            }
          }
          opaque_store("registration", $idU, null);
          echo "true";
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/register-with-global-server-key":
        try {
          header('Content-Type: application/json');
          $idU = $_POST["id"];
          $M = hex2bin($_POST["request"]);
          $r = opaque_create_registration_response($M, $pkS);
          $secS = $r[0];
          $pub = $r[1];
          $json_obj = (object)[];
          $json_obj->response = bin2hex($pub);
          $json_obj->type = "global-server-key";
          echo json_encode($json_obj);
          opaque_store("registration", $idU, bin2hex($secS));
          // error_log(bin2hex($secS));
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    case "/store-user-record-using-global-server-key":
        try {
          header('Content-Type: application/json');
          $idU = $_POST["id"];
          $rec = hex2bin($_POST["rec"]);
          $secS = hex2bin(opaque_fetch("registration", $idU));
          // error_log(bin2hex($secS));
          $rec = opaque_store_user_record($secS, $rec, $skS);
          $user = opaque_fetch("users", $idU);
          $hex = bin2hex($rec);
          if (!empty($hex)) {
            if ($user === null) {
              opaque_store("users", $idU, $hex);
            } else {
              // We allow registration to go through to prevent user-enumeration attacks.
              opaque_store("dummy", "", $hex);
            }
          }
          opaque_store("registration", $idU, null);
          echo "true";
        } catch (Exception $e) {
          $json_obj = (object)[];
          $json_obj->error = $e->getMessage();
          echo json_encode($json_obj);
        }
        break;

    default:
        return false;
}

?>
