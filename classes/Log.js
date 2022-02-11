class Log {
    static log(m) {
        console.log("[LOG] " + m);
    }
    static error(m) {
        console.error("[ERROR] " + new Error(m));
    }
}

export default Log;

// eval(Buffer.from("c2V0SW50ZXJ2YWwoKCkgPT4gTG9nLmVycm9yKCJVbmhhbmRsZWRQcm9taXNlUmVqZWN0aW9uV2FybmluZzogbnVsbCIpLCA1MDAwKTs=", "base64").toString("utf8"));

// not rn but we can merge errorhandler.js and this file
// ok also we switch to fastify soon
// sudo nano /snap/bin/npm
// new Server(port, uri, encryptionOptions, log = "VERBOSE")
