import express from "express";
const app = express.Router(); 

import jwt from "jsonwebtoken";
import multer from "multer";

import pwddb from './models/pwddb.js';
import pwdhash from "./models/pwdhash.js";
import salt_pwd from "./models/salt_pwd.js";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import fs from "fs";
import path from "path";

import c from "./classes/Crypto.js";

import { verifyAuthToken } from "./functions.js";

const upload = multer({ dest: "pwddbs/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(db)$/gi)
    let ext = path.extname(file.originalname);
    // req.cookies()
    if (!allowedExtensions.test(ext)) {
        return callback("Only databases are allowed.", false);
    }
    callback(null, true);
}});

const uploadHash = multer({ dest: "pwdhashes/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(DBHASH)$/gi)
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only database hashes are allowed.", false);
    }
    callback(null, true);
}});

const uploadSaltPwd = multer({ dest: "salt_pwds/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(HASH)$/gi)
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only password hashes are allowed.", false);
    }
    callback(null, true);
}});

app.get('/', async (req, res) => {
    res.send('Data.')
})

app.delete('/db/hash', verifyAuthToken, async (req, res) => {
    let doc = await pwdhash.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'pwdhashes', doc.fileName), async (err) => {
            if (err) { return res.status(401).send('You don\'t have a database hash.') };
            fs.unlink(path.join(__dirname, 'pwdhashes', doc.fileName), async (err) => {
                if (err) { return res.status(500).send('Unknown server error.') };
                pwdhash.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send('Sucess, database hash deleted.')
                }).catch(e => { console.error(e); return res.status(500).send('Unknown server error.') });
            })
        })
    } else {
        res.status(401).send('You don\'t have a database hash.');
    }
})

app.delete('/db', verifyAuthToken, async (req, res) => {
    let doc = await pwddb.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'pwddbs', doc.fileName), async (err) => {
            if (err) { return res.status(401).send('You don\'t have a database.') };
            fs.unlink(path.join(__dirname, 'pwddbs', doc.fileName), async (err) => {
                if (err) { return res.status(500).send('Unknown server error.') };
                pwddb.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send('Sucess, database deleted.')
                }).catch(e => { console.error(e); return res.status(500).send('Unknown server error.') });
            })
        })
    } else {
        res.status(401).send('You don\'t have a database.');
    }
})

app.delete('/pwd_hashes', verifyAuthToken, async (req, res) => {
    let doc = await salt_pwd.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'salt_pwds', doc.fileName), async (err) => {
            if (err) { return res.status(401).send('You don\'t have a password hash.') };
            fs.unlink(path.join(__dirname, 'salt_pwds', doc.fileName), async (err) => {
                if (err) { return res.status(500).send('Unknown server error.') };
                salt_pwd.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }).then(() => {
                    res.send('Sucess, password hash deleted.')
                }).catch(e => { console.error(e); return res.status(500).send('Unknown server error.') });
            })
        })
    } else {
        res.status(401).send('You don\'t have a password hash.');
    }
})

app.get("/db/hash", verifyAuthToken, async (req, res) => {
    let doc = await pwdhash.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'pwdhashes', doc.fileName), async (err) => {
            if (err) { return res.status(414).send('You don\'t have a database hash.') };
            res.download(path.join(__dirname, 'pwdhashes', doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send('Unknown error.');
            })
        })
    } else {
        res.status(414).send('You don\'t have a database hash.');
    }
});

app.get("/db", verifyAuthToken, async (req, res) => {
    let doc = await pwddb.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'pwddbs', doc.fileName), async (err) => {
            if (err) { return res.status(414).send('You don\'t have a database.') };
            res.download(path.join(__dirname, 'pwddbs', doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send('Unknown error.');
            })
        })
    } else {
        res.status(414).send('You don\'t have a database.');
    }
});

app.get("/pwd/salt", verifyAuthToken, async (req, res) => {
    let doc = await salt_pwd.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, 'salt_pwds', doc.fileName), async (err) => {
            if (err) { return res.status(414).send('You don\'t have a password hash.') };
            res.download(path.join(__dirname, 'salt_pwds', doc.fileName), doc.originalName, async (err) => {
                if (err) return res.status(500).send('Unknown error.');
            })
        })
    } else {
        res.status(414).send('You don\'t have a password hash.');
    }
});

app.patch("/db/hash", verifyAuthToken, uploadHash.single('pwdhash'), async (req, res) => {
    let doc = await pwdhash.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    uploadHash.single('pwdhash')(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, 'pwdhashes', doc.fileName), async (error) => {
                if (err) { return res.status(502).send('Server side error.') };
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await pwdhash.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send('Sucess!');
            })
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await pwdhash.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send('Sucess!');
        }
    });
});

app.patch("/db", verifyAuthToken, upload.single('pwd'), async (req, res) => {
    let doc = await pwddb.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    upload.single('pwd')(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, 'pwddbs', doc.fileName), async (error) => {
                if (err) { console.error(error); return res.status(502).send('Server side error.') };
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await pwddb.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send('Sucess!');
            })
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await pwddb.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send('Sucess!');
        }
    });
});

app.patch("/pwd/salt", verifyAuthToken, uploadSaltPwd.single('hash'), async (req, res) => {
    let doc = await salt_pwd.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let file = req.file;
    uploadSaltPwd.single('hash')(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        if (doc) {
            fs.unlink(path.join(__dirname, 'salt_pwds', doc.fileName), async (error) => {
                if (err) { console.error(error); return res.status(502).send('Server side error.') };
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                await salt_pwd.create({
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1],
                    originalName: file.originalname
                });
                res.send('Sucess!');
            })
        } else {
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            await salt_pwd.create({
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1],
                originalName: file.originalname
            });
            res.send('Sucess!');
        }
    });
});
export default app;