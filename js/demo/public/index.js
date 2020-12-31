(function () {
  "use strict";

  var form = document.getElementsByTagName("form")[0];
  var input_id = document.getElementsByName("id")[0];
  var input_pw = document.getElementsByName("pw")[0];
  var button_register = document.getElementsByName("register")[0];
  var button_login = document.getElementsByName("login")[0];
  var radio_register_type_with_password = document.getElementsByName(
    "register-type"
  )[0];
  var radio_register_type_without_password = document.getElementsByName(
    "register-type"
  )[1];
  var radio_register_type_with_global_server_key = document.getElementsByName(
    "register-type"
  )[2];
  var pre = document.getElementsByTagName("pre")[0];

  function submit(event) {
    event.preventDefault();
    return false;
  }

  function register(event) {
    if (radio_register_type_with_password.checked) {
      postMessage("register-with-password");
    } else if (radio_register_type_without_password.checked) {
      postMessage("register-without-password");
    } else if (radio_register_type_with_global_server_key.checked) {
      postMessage("register-with-global-server-key");
    } else {
      worker.onmessage({
        data: {
          printErr: "The registration type is invalid.",
        },
      });
    }
  }

  function login(event) {
    postMessage("login");
  }

  function postMessage(action) {
    var id = input_id.value;
    var pw = input_pw.value;
    // Send a message to index-worker.js.
    // https://developer.mozilla.org/en-US/docs/Web/API/Worker/postmessage
    pre.innerHTML = "<br>" + pre.innerHTML;
    worker.postMessage({ action: action, id: id, pw: pw });
  }

  form.addEventListener("submit", submit);
  button_register.addEventListener("click", register);
  button_login.addEventListener("click", login);

  // Use a web worker to prevent the main thread from blocking.
  // https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
  var worker = new Worker("index-worker.js");

  // Receive a message from index-worker.js.
  // https://developer.mozilla.org/en-US/docs/Web/API/Worker/onmessage
  var i = 0;
  worker.onmessage = function (e) {
    if (e.data.printErr)
      pre.innerHTML = i++ + ": " + e.data.printErr + "<br>" + pre.innerHTML;
    if (e.data.print)
      pre.innerHTML = i++ + ": " + e.data.print + "<br>" + pre.innerHTML;
  };
})();
