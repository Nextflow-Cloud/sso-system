import express from "express";
const app = express.Router(); 

import multer from "multer";

import pwdDbs from "./models/pwdDbs.js";
import pwdHashes from "./models/pwdHashes.js";
import pwdSalts from "./models/pwdSalts.js";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import fs from "fs";
import path from "path";

import c from "./classes/Crypto.js";

import { verifyAuthToken } from "./functions.js";

const upload = multer({ dest: "pwdDbs/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(db)$/gi);
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only databases are allowed.", false);
    }
    callback(null, true);
}});

const uploadHash = multer({ dest: "pwdHashes/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(DBHASH)$/gi);
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only database hashes are allowed.", false);
    }
    callback(null, true);
}});

const uploadSaltPwd = multer({ dest: "pwdSalts/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(HASH)$/gi);
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only password hashes are allowed.", false);
    }
    callback(null, true);
}});

// app.get("/", async (req, res) => {
//     res.send("Data.")
// })

app.delete("/db/hash", verifyAuthToken, async (req, res) => {
    let doc = await pwdHashes.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdHashes", doc.fileName), async (err) => {
            if (err) return res.status(401).send("You don't have a database hash.");
            fs.unlink(path.join(__dirname, "pwdHashes", doc.fileName), async (err) => {
                if (err) return res.status(500).send("Unknown server error.");
                pwdHashes.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send("Success, database hash deleted.");
                }).catch(e => { 
                    console.error(e); 
                    res.status(500).send("Unknown server error.") ;
                });
            })
        })
    } else {
        res.status(401).send("You don't have a database hash.");
    }
});

app.delete("/db", verifyAuthToken, async (req, res) => {
    let doc = await pwdDbs.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdDbs", doc.fileName), async (err) => {
            if (err) return res.status(401).send("You don't have a database.");
            fs.unlink(path.join(__dirname, "pwdDbs", doc.fileName), async (err) => {
                if (err) return res.status(500).send("Unknown server error.");
                pwdDbs.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send("Sucess, database deleted.");
                }).catch(e => { console.error(e); return res.status(500).send("Unknown server error.") });
            })
        })
    } else {
        res.status(401).send("You don't have a database.");
    }
});

app.delete("/pwd/salt", verifyAuthToken, async (req, res) => {
    let doc = await pwdSalts.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdSalts", doc.fileName), async (err) => {
            if (err) return res.status(401).send("You don't have a password hash.");
            fs.unlink(path.join(__dirname, "pwdSalts", doc.fileName), async (err) => {
                if (err) return res.status(500).send("Unknown server error.");
                pwdSalts.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send("Sucess, password hash deleted.");
                }).catch(e => { console.error(e); return res.status(500).send("Unknown server error.") });
            })
        })
    } else {
        res.status(401).send("You don't have a password hash.");
    }
});

app.get("/db/hash", verifyAuthToken, async (req, res) => {
    let doc = await pwdHashes.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdHashes", doc.fileName), async (err) => {
            if (err) return res.status(414).send("You don't have a database hash.");
            res.download(path.join(__dirname, "pwdHashes", doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send("Unknown error.");
            });
        });
    } else {
        res.status(414).send("You don't have a database hash.");
    }
});

app.get("/db", verifyAuthToken, async (req, res) => {
    let doc = await pwdDbs.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdDbs", doc.fileName), async (err) => {
            if (err) return res.status(414).send("You don't have a database.");
            res.download(path.join(__dirname, "pwdDbs", doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send("Unknown error.");
            });
        });
    } else {
        res.status(414).send("You don't have a database.");
    }
});

app.get("/pwd/salt", verifyAuthToken, async (req, res) => {
    let doc = await pwdSalts.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "pwdSalts", doc.fileName), async (err) => {
            if (err) return res.status(414).send("You don't have a password hash.");
            res.download(path.join(__dirname, "pwdSalts", doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send("Unknown error.");
            });
        });
    } else {
        res.status(414).send("You don't have a password hash.");
    }
});

app.patch("/db/hash", verifyAuthToken, uploadHash.single("pwdHashes"), async (req, res) => {
    let doc = await pwdHashes.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    uploadHash.single("pwdHashes")(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, "pwdHashes", doc.fileName), async (error) => {
                if (err) return res.status(502).send("Server side error.");
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await pwdHashes.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send("Sucess!");
            });
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await pwdHashes.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send("Sucess!");
        }
    });
});

app.patch("/db", verifyAuthToken, upload.single("pwd"), async (req, res) => {
    let doc = await pwdDbs.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    upload.single("pwd")(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, "pwdDbs", doc.fileName), async (error) => {
                if (err) { 
                    console.error(error); 
                    return res.status(502).send("Server side error.");
                }
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await pwdDbs.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send("Success!");
            });
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await pwdDbs.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send("Success!");
        }
    });
});

app.patch("/pwd/salt", verifyAuthToken, uploadSaltPwd.single("hash"), async (req, res) => {
    let doc = await pwdSalts.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    uploadSaltPwd.single("hash")(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, "pwdSalts", doc.fileName), async (error) => {
                if (err) { 
                    console.error(error); 
                    return res.status(502).send("Server side error.");
                }
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await pwdSalts.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send("Success!");
            });
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await pwdSalts.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send("Success!");
        }
    });
});

export default app;
