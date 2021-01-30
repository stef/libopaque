    });
    // https://github.com/jedisct1/libsodium.js/blob/master/wrapper/libsodium-post.js
    if (
      typeof process === "object" &&
      typeof process.removeAllListeners === "function"
    ) {
      process.removeAllListeners("uncaughtException");
      process.removeAllListeners("unhandledRejection");
    }
    return Module;
  }

  if (typeof define === "function" && define.amd) {
    define(["exports"], exposeLibopaque);
  } else if (
    typeof exports === "object" &&
    typeof exports.nodeName !== "string"
  ) {
    exposeLibopaque(exports);
  } else {
    root.libopaque = exposeLibopaque(
      root.libopaque_mod || (root.commonJsStrict = {})
    );
  }
})(this);
