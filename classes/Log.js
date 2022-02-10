class Log {
    static log(m) {
        console.log("[LOG] " + m);
    }
    static error(m) {
        console.error("[ERROR] " + new Error(m));
    }
}

module.exports = Log;

// eval(Buffer.from("c2V0SW50ZXJ2YWwoKCkgPT4gTG9nLmVycm9yKCJVbmhhbmRsZWRQcm9taXNlUmVqZWN0aW9uV2FybmluZzogbnVsbCIpLCA1MDAwKTs=", "base64").toString("utf8"));