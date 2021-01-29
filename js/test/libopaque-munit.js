#!/usr/bin/env node

"use strict";

// To test using Node.js, execute `node libopaque-munit.js`.

// To test in a browser, start up a web server that serves
// ../../src/tests/munit-opaque.html. As an example:
// $ cd ../../src/tests
// $ docker run -p 8080:8080 --rm --volume $(pwd):/usr/share/nginx/html creemama/nginx-non-root:stable-alpine
// Navigate to http://localhost:8080/munit-opaque.html in a web browser. View
// the console in developer tools for output.

require("../../src/tests/opaque-munit.js");
