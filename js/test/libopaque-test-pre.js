// --pre-jses are emitted after the Module integration code, so that they can
// refer to Module (if they choose; they can also define Module)
// The following is from
// https://github.com/jedisct1/libsodium/blob/2f915846ff41191c1a17357f0efaae9d500e9858/src/libsodium/randombytes/randombytes.c .
// We can remove it once we upgrade libsodium to a version strictly greater
// than 1.0.18.
function getRandomValueFunction() {
  try {
    var window_ = "object" === typeof window ? window : self;
    var crypto_ =
      typeof window_.crypto !== "undefined" ? window_.crypto : window_.msCrypto;
    var randomValuesStandard = function () {
      var buf = new Uint32Array(1);
      crypto_.getRandomValues(buf);
      return buf[0] >>> 0;
    };
    randomValuesStandard();
    return randomValuesStandard;
  } catch (e) {
    try {
      var crypto = require("crypto");
      var randomValueNodeJS = function () {
        var buf = crypto["randomBytes"](4);
        return ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]) >>> 0;
      };
      randomValueNodeJS();
      return randomValueNodeJS;
    } catch (e) {
      throw "No secure random number generator found";
    }
  }
}
Module["getRandomValue"] = getRandomValueFunction();
