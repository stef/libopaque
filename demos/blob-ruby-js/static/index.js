(function () {
  "use strict";

  var button_fetch = document.getElementsByName("fetch")[0];
  var pre = document.getElementsByTagName("pre")[0];

  function fetch(event) {
    postMessage("fetch");
  }

  function postMessage(action) {
    var pw = document.getElementById("pw").value;
    // Send a message to index-worker.js.
    // https://developer.mozilla.org/en-US/docs/Web/API/Worker/postmessage
    pre.innerHTML = "<br>" + pre.innerHTML;
    worker.postMessage({ action: action, pw: pw });
  }

  button_fetch.addEventListener("click", fetch);

  // Use a web worker to prevent the main thread from blocking.
  // https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
  var worker = new Worker("/index-worker.js");

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
