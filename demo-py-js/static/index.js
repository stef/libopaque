(function () {
  "use strict";

  var button_register = document.getElementsByName("register")[0];
  var button_login = document.getElementsByName("authenticate")[0];
  var pre = document.getElementsByTagName("pre")[0];

  function register(event) {
    postMessage("register");
  }

  function login(event) {
    postMessage("login");
  }

  function postMessage(action) {
    var id = document.getElementById("id").value;
    var pw = document.getElementById("pw").value;
    // Send a message to index-worker.js.
    // https://developer.mozilla.org/en-US/docs/Web/API/Worker/postmessage
    pre.innerHTML = "<br>" + pre.innerHTML;
    worker.postMessage({ action: action, id: id, pw: pw });
  }

  button_register.addEventListener("click", register);
  button_login.addEventListener("click", login);

  // Use a web worker to prevent the main thread from blocking.
  // https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
  var worker = new Worker("/static/index-worker.js");

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
