import express from "express";
const app = express.Router();

import multer from "multer";
import cookieParser from "cookie-parser";

import jwt from "jsonwebtoken";
import n2fa from "node-2fa";

import sharp from "sharp";
import qr from "qrcode";

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import c from "./classes/Crypto.js";

import Store from "./classes/Store.js";
const tokenStore = new Store("token");
const mfaStore = new Store("mfa");
const deleteMFA = new Store("delete");

import avatars from "./models/avatars.js";
import blacklist from "./models/blacklist.js";
import forgotPasswords from "./models/forgotPasswords.js";
import profiles from "./models/profiles.js";
import users from "./models/users.js";

import { createTransport, verifyAuthToken } from "./functions.js";

const SALT_T = process.env.SALT_T;
const KEY = Buffer.from(process.env.KEY, "base64");
const SERVER_PRIVATE_KEY = process.env.PRIVATE;
const SERVER_PUBLIC_KEY = process.env.PUBLIC;
const IV = Buffer.from(process.env.IV, "base64");

const upload = multer({ dest: "avatars/", limits: { fileSize: 8388608 }, fileFilter: (req, file, callback) => {
    const allowedExtensions = new RegExp(/.(jpg|png|jpeg|gif|jfif)$/gi)
    let ext = path.extname(file.originalname);
    if (!allowedExtensions.test(ext)) {
        return callback("Only images are allowed.", false);
    }
    callback(null, true);
}});
app.use(cookieParser());

const easteregg = eval(Buffer.from("WyJJIGNhbiBmZWVsIGl0IGNvbWluZyBpbiB0aGUgYWlyIHRvbmlnaHQiLCAiSSd2ZSBiZWVuIHdhaXRpbmcgZm9yIHRoaXMgbW9tZW50IGZvciBhbGwgbXkgbGlmZSIsICJDYW4geW91IGZlZWwgaXQgY29taW5nIGluIHRoZSBhaXIgdG9uaWdodCJd", "base64").toString("binary"));

app.post("/login", async (req, res) => {
    if (!req.body || !req.body.stage) {
        return res.status(400).send(JSON.stringify({ error: "Please send a stage inside a JSON body with form parameters" }));
    }
    if (req.body.stage === 1) {
        var authorizedHeaders = req.body;
        var email = authorizedHeaders.email;
        var emailHash = await c.hashPasswordSalt(email, process.env.SALT);
        var user = await users.findOne({ emailHash });
        if (user) {
            var token = await c.generateToken(email);
            await tokenStore.store(token, {
                time: Date.now() + 1000 * 60 * 60,
                email, emailHash
            }); 
            res.status(200).json({
                continueToken: token
            }); 
        } else {
            res.sendStatus(401);
        }
    } else if (req.body.stage === 2) {
        var authorizedHeaders = req.body;
        var token = authorizedHeaders.continueToken;
        var fetchedToken = await tokenStore.get(token);
        if (!fetchedToken || fetchedToken.time < Date.now()) {
            return res.status(403).send(easteregg[crypto.randomInt(easteregg.length)]);
        }
        var password = authorizedHeaders.password;
        var user = await users.findOne({ emailHash: fetchedToken.emailHash }); 
        var verify = await c.verifyPassword(password, user.passwordHash);
        if (verify) {
            var userObj = {
                id: c.decrypt(user.idEncrypted, KEY),
                username: c.decrypt(user.usernameEncrypted, KEY, IV),
                email: fetchedToken.email
            };
            if (c.decrypt(user.twoFactorEncrypted, KEY, IV) == "true" && c.verify(user.twoFactorEncrypted, user.twoFactorSignature, SERVER_PUBLIC_KEY)) {
                var token = await c.generateToken(fetchedToken.email);
                await mfaStore.store(token, {
                    time: Date.now() + 1000 * 60 * 60,
                    email: fetchedToken.email,
                    emailHash: fetchedToken.emailHash
                }); 
                res.status(200).json({
                    continueToken: token,
                    mfaEnabled: true
                }); 
            } else {
                jwt.sign({ user: userObj }, process.env.KEY, (err, token) => {
                    if (err) {
                        console.enhancedError("Express.Login", err);
                        res.status(500).send("Oopsies our backend had some problems, please try again later");
                    }

                    res.cookie("token", token, { domain: ".nextflow.cloud", secure: true, expires: new Date(9676800000000) });
                    
                    res.status(200).json({
                        token: token,
                        mfaEnabled: false
                    });
                });
            }
        } else {
            res.status(401).send(easteregg[crypto.randomInt(easteregg.length)]);
        } 
    } else if (req.body.stage === 3) {
        var authorizedHeaders = req.body;
        var token = authorizedHeaders.continueToken;
        var fetchedToken = await mfaStore.get(token);
        if (!fetchedToken || fetchedToken.time < Date.now()) {
            return res.sendStatus(403);
        }
        var password = authorizedHeaders.password;
        var code = authorizedHeaders.code;
        var user = await users.findOne({ emailHash: fetchedToken.emailHash });
        var verify = false;
        if (user) verify = await c.verifyPassword(password, user.passwordHash);
        if (verify && (c.decrypt(user.twoFactorEncrypted, KEY, IV) == "true" && 
            c.verify(user.twoFactorEncrypted, user.twoFactorSignature, SERVER_PUBLIC_KEY)) && 
            (c.decrypt(user.twoFactorCodeEncrypted, KEY, IV) !== "" && 
            c.verify(user.twoFactorCodeEncrypted, user.twoFactorCodeSignature, SERVER_PUBLIC_KEY))) {
            var token = n2fa.verifyToken(c.decrypt(user.twoFactorCodeEncrypted, KEY, IV), code);
            if (token) {
                var userObj = {
                    id: c.decrypt(user.idEncrypted, KEY),
                    username: c.decrypt(user.usernameEncrypted, KEY, IV),
                    email: fetchedToken.email.toString()
                };
                jwt.sign({ user: userObj }, process.env.KEY, (err, token) => {
                    if (err) {
                        console.enhancedError("Express.Login", err);
                        res.status(500).send("Oopsies our backend had some problems, please try again later");
                    }
                    res.cookie("token", token, { domain: ".nextflow.cloud", secure: true, expires: new Date(9676800000000) });
                    res.status(200).json({
                        token: token
                    });
                });
            } else {
                if (user.twoFactorBackupCodesHashed.findIndex(r => c.verifyPassword(code, r) === true) !== -1) {
                    let index = user.twoFactorBackupCodesHashed.findIndex(r => c.verifyPassword(code, r) === true);
                    let authenticatedCode = user.twoFactorBackupCodesHashed[index];
                    if (c.verify(authenticatedCode, user.twoFactorBackupCodesSignature[index], SERVER_PUBLIC_KEY)) {
                        var userObj = {
                            id: c.decrypt(user.idEncrypted, KEY),
                            username: c.decrypt(user.usernameEncrypted, KEY, IV),
                            email: fetchedToken.email.toString()
                        };
                        jwt.sign({ user: userObj }, process.env.KEY, (err, token) => {
                            if (err) {
                                console.enhancedError("Express.Login", err);
                                res.status(500).send("Oopsies our backend had some problems, please try again later");
                            }
                            res.cookie("token", token, { domain: ".nextflow.cloud", secure: true, expires: new Date(9676800000000) });
                            res.status(200).json({
                                token: token
                            });
                        });
                    } else {
                        res.sendStatus(500);
                    }
                } else {
                    res.sendStatus(401);
                }
            }
        } else {
            res.sendStatus(401);
        }
    }
});

app.patch("/user/password", verifyAuthToken, async (req, res) => {
    var oldPassword = req.body.old;
    if (!oldPassword) {
        return res.status(400).send("Please provide your old password");
    }
    var password = req.body.password;
    jwt.verify(req.token, process.env.KEY, async (err, authData) => {
        if (err) {
            res.sendStatus(401);
        } else {
            let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(authData.user.email, process.env.SALT) });
            if (doc) {
                if (c.verifyPassword(oldPassword, doc.passwordHash)) {
                    await users.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(authData.user.email, process.env.SALT) }, { passwordHash: await c.hashPassword(password) });
                    res.send("Successfully changed your password!");
                } else {
                    res.status(401).send("Incorrect current password!");
                }
            } else {
                res.status(401).send("User does not exist");
            }
        }
    })
});

app.patch("/user/avatar", verifyAuthToken, upload.single("avatar"), async (req, res) => {
    let doc = await avatars.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let val = doc ? true : false; 
    let file = req.file;
    if (!val) {
        upload.single("avatar")(req, res, async (err) => {
            if (err) return res.status(413).send("Invalid file.");
            jwt.verify(req.token, process.env.KEY, async (error, result) => {
                if (error) return console.enhancedError("Express.User.Avatar", error);
                let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
                let idHash = await c.hashPasswordSalt(result.user.id, process.env.SALT);
                let fileType = path.extname(file.originalname).split(".")[1];
                await avatars.create({
                    idHash,
                    emailHash,
                    fileName: file.filename,
                    fileType: path.extname(file.originalname).split(".")[1] === "gif" ? "gif" : "png",
                    originalName: file.originalname
                });
                if (fileType.toLowerCase() === "gif") {
                    res.send("Success!");
                } else {
                    sharp(path.join(__dirname, "/avatars", file.filename)).resize({ height: 512, width: 512 }).toFormat("png").toFile(file.filename).then((resul) => {
                        fs.copyFile(file.filename, path.join(__dirname, "/avatars", file.filename), e => {
                            if (e) res.status(500).send("Server error");
                            fs.unlink(file.filename, (er) => {
                                if (er) res.status(500).send("Server error");
                                res.send("Success!");
                            });
                        });
                    }).catch(() => res.status(500).send("Server error"));
                }
            });
        });
        return;
    }
    upload.single("avatar")(req, res, async (err) => {
        if (err) return res.status(413).send("Invalid file.");
        jwt.verify(req.token, process.env.KEY, async (error, result) => {
            if (error) return console.enhancedError("Express.User.Avatar", error);
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            let idHash = await c.hashPasswordSalt(result.user.id, process.env.SALT);
            await avatars.create({
                idHash,
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1] === "gif" ? "gif" : "png",
                originalName: file.originalname
            });
            res.send("Success!");
            await avatars.findOneAndDelete({ emailHash });
            return fs.unlink(path.join(__dirname, "/avatars", doc.fileName), err => {
                if (err) {
                    console.enhancedError("Express.User.Avatar", err);
                    return res.status(500).send("Error!");
                }
            });
        });
    });
});

app.post("/user/avatar", verifyAuthToken, upload.single("avatar"), async (req, res) => {
    let file = req.file;
    let doc = await avatars.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        return fs.unlink(path.join(__dirname, file.path), err => {
            if (err) {
                console.enhancedError("Express.User.Avatar", err);
                return res.status(500).send("Error!");
            } else {
                return res.status(400).send("You can't create a profile picture if you already have one.");
            }
        });
    }
    upload.single("avatar")(req, res, async err => {
        if (err) return res.status(413).send("Invalid file.");
        jwt.verify(req.token, process.env.KEY, async (error, result) => {
            if (error) return console.enhancedError("Express.User.Avatar", error);
            let emailHash = await c.hashPasswordSalt(req.email, process.env.SALT);
            let idHash = await c.hashPasswordSalt(result.user.id, process.env.SALT);
            let fileType = path.extname(file.originalname).split(".")[1];
            await avatars.create({
                idHash,
                emailHash,
                fileName: file.filename,
                fileType: path.extname(file.originalname).split(".")[1] === "gif" ? "gif" : "png",
                originalName: file.originalname
            });
            if (fileType.toLowerCase() === "gif") {
                res.send("Success!");
            } else {
                sharp(path.join(__dirname, "/avatars", file.filename)).resize({ height: 512, width: 512 }).toFormat("png").toFile(file.filename).then(() => { 
                    fs.copyFile(file.filename, path.join(__dirname, "/avatars", file.filename), (e) => {
                        if (e) res.status(500).send("Server error");
                        fs.unlink(file.filename, (er) => {
                            if (er) res.status(500).send("Server error");
                            res.send("Success!");
                        });
                    });
                }).catch((e) => res.status(500).send("Server error"));
            }
        });
    });
});

app.get("/user/:id/avatar", async (req, res) => {
    let checkExists = await users.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
    if (!checkExists) return res.status(407).send("User was not found.");
    let doc = await avatars.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
    if (doc) {
        fs.access(path.join(__dirname, "/avatars", doc.fileName), fs.constants.F_OK, (error) => {
            if (error) throw error;
            res.setHeader("content-type", "image/" + doc.fileType);
            res.sendFile(path.join(__dirname, "/avatars", doc.fileName));
        });
    } else {
        res.sendFile(path.join(__dirname, "default.jpg"));
    }
});

app.get("/user/avatar", verifyAuthToken, async (req, res) => {
    let doc = await avatars.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    jwt.verify(req.token, process.env.KEY, (err, result) => {
        if (err) return res.status(500).send("There was a error on our side, we will work on fixing that bug.");
        if (doc) {
            fs.access(path.join(__dirname, "/avatars", doc.fileName), fs.constants.F_OK, (error) => {
                if (error) throw error;
                res.setHeader("content-type", "image/" + doc.fileType);
                res.sendFile(path.join(__dirname, "/avatars", doc.fileName));
            })
        } else {
            res.sendFile(path.join(__dirname, "default.jpg"));
        }
    });
});

app.delete("/user/avatar", verifyAuthToken, async (req, res) => {
    let doc = await avatars.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        fs.unlink(path.join(__dirname, "/avatars", doc.fileName), async (err) => {
            if (err) { 
                console.enhancedError("Express.User.Avatar", err); 
                res.status(500).send("Server side error.");
            } else {
                await avatars.findOneAndDelete({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
                res.send("Deleted avatar!");
            }
        })
    } else {
        res.status(412).send("Can't delete nonexistent profile picture");
    }
});

app.post("/forgot/password", async (req, res) => {
    let email = req.body.email;
    let email_template = `Hi {name},

    You recently requested to reset your password for your account.

    Please click the following link to reset your password:

    {link}

    If you did not request a password reset, please ignore this email.

    Thanks,

    The Nextflow Team`;
    let html_template = `
    <!doctype html>
    <html lang="en-US">
    
    <head>
        <meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
        <title>Reset Password!</title>
        <meta name="description" content="Reset Password Email">
        <style type="text/css">
            body {
              background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
              min-height: 100vh;
            }
            taable {
              background: linear-gradient(90deg,#f64f59,#c471ed,#12c2e9);
              min-height:100vh;
            }
            table {
              opacity: 1;
            }
            .button {
              background-color: #4CAF50; /* Green */
              margin-top: 45px;
              border: none;
              color: white;
              padding: 16px 32px;
              text-align: center;
              text-decoration: none;
              display: inline-block;
              font-size: 16px;
              margin: 4px 2px;
              transition-duration: 0.4s;
              cursor: pointer;
            }
            .button1 {
                background:#20e277;
                text-decoration:none !important;
                font-weight:500; 
                margin-top:45px; 
                color:#fff;
                text-transform:uppercase; 
                font-size:14px;
                padding:10px 134px;
                display:inline-block;
                color: white;
                border-radius:50px;
                background-color: #4CAF50;
                border: 2px solid #4CAF50;
                transition-duration: 0.5s;
            }
            
            .button1:hover {
                background-color: white; 
                transition-duration: 0.5s;
                color: black; 
            }
            a:hover {text-decoration: underline !important;}
        </style>
    </head>
    
    <body marginheight="0" topmargin="0" marginwidth="0" style="margin: 0px; background-color: #f2f3f8;" leftmargin="0">
        <!--100% body table-->
        <table cellspacing="0" border="0" cellpadding="0" id="aaa" width="100%" 
            style="@import url(https://fonts.googleapis.com/css?family=Rubik:300,400,500,700|Open+Sans:300,400,600,700); font-family: "Open Sans", sans-serif;">
            <tr>
                <td>
                    <table style="max-width:670px;  margin:0 auto;" width="100%" border="0"
                        align="center" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                        <tr id="a4">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td>
                                <table width="95%" border="0" align="center" cellpadding="0" cellspacing="0"
                                    style="max-width:670px;background:#fff; border-radius:20px; text-align:center;-webkit-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);-moz-box-shadow:0 6px 18px 0 rgba(0,0,0,.06);box-shadow:0 6px 18px 0 rgba(0,0,0,.06);">
                                    <tr>
                                        <td style="height:80px;"></td>
                                    </tr>
                                    <tr>
                                        <td style="text-align:center;">
                                          <a href="https://www.nextflow.cloud" title="logo" target="_blank">
                                            <img width="60" src="https://i.ibb.co/hL4XZp2/android-chrome-192x192.png" alt="logo">
                                          </a>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:80px;">&nbsp;</td>
                                    </tr>
                                    <tr>
                                        <td style="padding:0 35px;">
                                            <h1 style="color:#1e1e2d; font-weight:500; margin:0;font-size:32px;font-family:"Rubik",sans-serif;">You requested to reset your password</h1>
                                            <span
                                                style="display:inline-block; vertical-align:middle; margin:29px  26px; border-bottom:1px solid #cecece; width:400px;"></span>
                                            <p style="color:#455056; font-size:15px;line-height:24px; margin:0;">
                                                We cannot simply send you your old password. A unique link to reset your
                                                password has been generated for you. To reset your password, click the
                                                following link and follow the instructions.
                                            </p>
                                            <button class="button1">
                                                <a href={link}>Reset Password</a>
                                            </button>
                                            <!-- <a href="javascript:void(0);" -->
                                                <!-- style="background:#20e277;text-decoration:none !important; font-weight:500; margin-top:45px; color:#fff;text-transform:uppercase; font-size:14px;padding:10px 34px;display:inline-block;border-radius:50px;">Reset -->
                                                <!-- Password</a> -->
                                            
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="height:100px;">&nbsp;</td>
                                    </tr>
                                </table>
                            </td>
                        <tr id="a2">
                            <td style="height:20px;">&nbsp;</td>
                        </tr>
                        <tr>
                            <td style="text-align:center;">
                                <p style="font-size:14px; color:rgba(255, 255, 255, 1); line-height:18px; margin:0 0 0;">&copy; 2022 Nextflow Technologies B.V. All rights reserved.</p>
                            </td>
                        </tr>
                        <tr id="a1">
                            <td style="height:80px;">&nbsp;</td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
        <!--/100% body table-->
    </body>
    
    </html>`;
    let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(email, process.env.SALT) });
    if (doc) {
        let idHa = crypto.randomUUID() + crypto.randomUUID();
        await forgotPasswords.create({
            idHash: await c.hashPasswordSalt(idHa, process.env.SALT),
            emailEncrypted: c.encrypt(email, KEY, IV),
            expires: new Date(Date.now() + (1000 * 60 * 60 * 3))
        });
        let message = {
            from: "Nextflow Technologies <system@nextflow.cloud>",
            to: email,
            subject: "Forgot password?",
            html: html_template.replace("{link}", `https://secure.nextflow.cloud/forgot/${idHa}`)
        };
        const sender = await createTransport();
        sender.sendMail(message, async (err, info) => {
            if (err) {
                console.enhancedError("Express.Forgot.Password", err);
            }
        });
        res.status(200).send("Sent forget password to that email, if it exists!");
    } else {
        res.status(200).send("Sent forget password to that email, if it exists!");
    }
})

app.post("/reset/:code", async (req, res) => { 
    let code = req.params.code;
    let password = req.body.password;
    let doc = await forgotPasswords.findOne({ idHash: await c.hashPasswordSalt(code, process.env.SALT) });
    if (doc) {
        if (doc.expires.getMilliseconds() <= Date.now() + (1000 * 60 * 60 * 3) ) {
            let email = c.decrypt(doc.emailEncrypted, KEY, IV);
            let docer = await users.findOne({ emailHash: (await c.hashPasswordSalt(email, process.env.SALT)) });
            if (!docer) {
                res.status(401).send("Code associated with that account doesn't work due to account being deleted.");
                await forgotPasswords.findOneAndDelete({ idHash: await c.hashPasswordSalt(code, process.env.SALT) });
            } else {
                const passwordHashed = await c.hashPassword(password);
                await users.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(email, process.env.SALT) }, { passwordHash: passwordHashed });
                await forgotPasswords.findOneAndDelete({ idHash: await c.hashPasswordSalt(code, process.env.SALT) });
                res.sendStatus(200);
            }
        } else {
            res.status(401).send("That code does not exist anymore!");
            await forgotPasswords.findOneAndDelete({ idHash: await c.hashPasswordSalt(code, process.env.SALT) });
        }
    } else {
        res.status(401).send("That code does not exist anymore!");
    }
});

app.post("/user", async (req, res) => { 
    let authorizedHeaders = req.body;
    let email = authorizedHeaders.email;
    let username = authorizedHeaders.username;
    let password = authorizedHeaders.password;
    let name = authorizedHeaders.name;
    let doc = await users.findOne({ emailHash: (await c.hashPasswordSalt(email, process.env.SALT)) });
    if (!doc) {
        var hash = await c.hashPassword(username);
        var encrypted = c.encrypt(username, KEY, IV);
        var emailEncrypted = c.encrypt(email, KEY, IV);
        var emailHash = await c.hashPasswordSalt(email, process.env.SALT);
        var passwordHash = await c.hashPassword(password);
        var nameEncrypted = c.encrypt(name, KEY, IV);
        var twoFactorEncrypted = c.encrypt("false", KEY, IV);
        var twoFactorSignature = c.sign(twoFactorEncrypted, SERVER_PRIVATE_KEY);
        var twoFactorCodeEncrypted = c.encrypt("", KEY, IV);
        var twoFactorCodeSignature = c.sign(twoFactorCodeEncrypted, SERVER_PRIVATE_KEY)
        var id = c.generateKey();
        var idHash = await c.hashPasswordSalt(id, process.env.SALT);
        var idEncrypted = c.encrypt(id, KEY);
        var emailPublic = c.encrypt("false", KEY);
        var emailPublicSignature = c.sign(emailPublic, SERVER_PRIVATE_KEY);
        var descriptionEncrypted = c.encrypt("", KEY);
        var websiteEncrypted = c.encrypt("", KEY);
        await users.create({
            idHash,
            idEncrypted,
            usernameHash: hash,
            usernameEncrypted: encrypted,
            emailEncrypted,
            emailHash,
            nameEncrypted,
            passwordHash,
            twoFactorSignature,
            twoFactorEncrypted,
            twoFactorCodeEncrypted,
            twoFactorCodeSignature,
            twoFactorBackupCodesHashed: [],
            twoFactorBackupCodesEncrypted: [],
            twoFactorBackupCodesSignature: [],
        });
        await profiles.create({
            idHash,
            emailHash,
            emailEncrypted,
            emailPublic,
            emailPublicSignature,
            descriptionEncrypted,
            websiteEncrypted
        });
        var userObj = {
            id: id,
            username: username,
            email: email
        };
        jwt.sign({ user: userObj }, process.env.KEY, (err, token) => {
            res.cookie("token", token, { domain: ".nextflow.cloud", secure: true, expires: new Date(9676800000000) });

            res.status(200).json({
                token: token
            });
        });
    } else {
        res.status(409).send("Account already exists. If you forgot the password please go to forget password!");
    }
});

app.get("/user/:id?/email", verifyAuthToken, async (req, res) => {
    if (req.params.id) {
        let prof = await profiles.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
        if (prof) {
            let tmpemail = "";
            if (c.decrypt(prof.emailPublic, KEY) === "true") {
                tmpemail = c.decrypt(prof.emailEncrypted, KEY);
            }
            let emailAvailable = false;
            if (c.decrypt(prof.emailPublic, KEY) === "true" && c.verify(prof.emailPublic, prof.emailPublicSignature, SERVER_PUBLIC_KEY)) {
                emailAvailable = true;
            }
            res.send({ email: tmpemail, emailAvailable })
        } else {
            res.status(409).send("User does not exist.");
        }
    } else {
        jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
            if (err) {
                res.sendStatus(401);
            } else {
                res.send(authData.user.email); 
            }
        });
    }
});

app.get("/user/mfa/check", verifyAuthToken, async (req, res) => {
    let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        if (c.verify(doc.twoFactorEncrypted, doc.twoFactorSignature, SERVER_PRIVATE_KEY) && c.verify(doc.twoFactorCodeEncrypted, doc.twoFactorCodeSignature, SERVER_PRIVATE_KEY)) {
            let val = c.decrypt(doc.twoFactorEncrypted, KEY, IV);
            if (val.toLowerCase() === "true") {
                res.status(200).send({ mfa: true });
            } else if (val.toLowerCase() === "false") {
                res.status(200).send({ mfa: false });
            } else {
                res.status(500).send("Error on server side!");
            }
        }
    } else {
        res.sendStatus(401);
    }
});

app.patch("/user/mfa/toggle", verifyAuthToken, async (req, res) => {
    let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    let password = req.body.password;
    if (doc) {
        if (await c.verifyPassword(password, doc.passwordHash)) {
            if (c.verify(doc.twoFactorEncrypted, doc.twoFactorSignature, SERVER_PRIVATE_KEY) && c.verify(doc.twoFactorCodeEncrypted, doc.twoFactorCodeSignature, SERVER_PRIVATE_KEY)) {
                let val = c.decrypt(doc.twoFactorEncrypted, KEY, IV);
                if (val.toLowerCase() === "true") {
                    val = c.encrypt("false", KEY);
                    let valSigned = c.sign(val, SERVER_PRIVATE_KEY);
                    var twoFactorCodeEncrypted = c.encrypt("", KEY, IV);
                    var twoFactorCodeSignature = c.sign(twoFactorCodeEncrypted, SERVER_PRIVATE_KEY);
                    await users.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }, {
                        twoFactorSignature: valSigned,
                        twoFactorEncrypted: val,
                        twoFactorCodeEncrypted: twoFactorCodeEncrypted,
                        twoFactorCodeSignature: twoFactorCodeSignature,
                        twoFactorBackupCodesHashed: [],
                        twoFactorBackupCodesEncrypted: [],
                        twoFactorBackupCodesSignature: [],
                    });
                    res.status(200).send({ mfa: false });
                } else if (val.toLowerCase() === "false") {
                    let secret = n2fa.generateSecret({ name: "Nextflow Authentication", "account": req.email });
                    val = c.encrypt("true", KEY);
                    let valSigned = c.sign(val, SERVER_PRIVATE_KEY)
                    const qrcode = await qr.toDataURL(secret.uri);
                    let codaEncrypted = c.encrypt(secret.secret, KEY);
                    let codaSigned = c.sign(codaEncrypted, SERVER_PRIVATE_KEY);
                    let codes = [];
                    for (let i = 0; i < 6; i++) {
                        codes.push(c.generateBackupCodes());
                    }
                    var codesHashed = await Promise.all(codes.map(code => c.hashPassword(code)));
                    var codesEncrypted = codesHashed.map(code => c.encrypt(code, KEY));
                    var codesSigned = codesHashed.map(code => c.sign(code, SERVER_PRIVATE_KEY));
                    await users.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }, {
                        twoFactorSignature: valSigned,
                        twoFactorEncrypted: val,
                        twoFactorCodeEncrypted: codaEncrypted,
                        twoFactorCodeSignature: codaSigned,
                        twoFactorBackupCodesHashed: codesHashed,
                        twoFactorBackupCodesEncrypted: codesEncrypted,
                        twoFactorBackupCodesSignature: codesSigned
                    });
                    res.status(200).send({ mfa: true, qrcode: qrcode, secret: secret.secret, secret_uri: secret.uri, codes: codes.join(",") })
                } else {
                    res.status(500).send("Error on server side!");
                }
            } else {
                res.sendStatus(500);
            }
        } else {
            res.status(401).send("Invalid password!");
        }
    } else {
        res.sendStatus(401);
    }
});

app.post("/validate", (req, res) => {
    var token = req.body.token;
    jwt.verify(token, process.env.KEY, err => {
        if (err) return res.sendStatus(401);
        else return res.sendStatus(200);
    });
}); 

app.delete("/user", verifyAuthToken, async (req, res) => {
    if (!req.body || !req.body.stage) {
        return res.status(400).send("Missing stage");
    }
    if (req.body.stage === 1) {
        let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) })
        if (doc) {
            if (await c.verifyPassword(req.body.password, doc.passwordHash)) {
                jwt.verify(req.token, process.env.KEY, async (err, authData) => {
                    if (err) return res.sendStatus(401);
                    else { 
                        if (c.decrypt(doc.twoFactorEncrypted, KEY, IV) == "true" && c.verify(doc.twoFactorEncrypted, doc.twoFactorSignature, SERVER_PUBLIC_KEY)) {
                            var token = await c.generateToken(req.email);
                            await deleteMFA.store(token, {
                                time: Date.now() + 1000 * 60 * 60,
                                email: req.email,
                                emailHash: await c.hashPasswordSalt(req.email, process.env.SALT)
                            }); 
                            res.status(200).json({
                                continueToken: token,
                                mfaEnabled: true
                            });
                        } else {
                            let hashedData = await c.hashPasswordSalt(authData.user.email, process.env.SALT);
                            profiles.deleteOne({ emailHash: hashedData });
                            users.deleteOne({ emailHash: hashedData }).then(() => res.status(200).send({})).catch(() => res.sendStatus(500));
                            res.cookie("token", "", { domain: ".nextflow.cloud", secure: true, expires: new Date(Date.now() + 1) });
                            await blacklist.create({
                                emailHash: hashedData,
                                tokenHash: await c.hashPasswordSalt(req.token, SALT_T)
                            });
                        }
                    }
                });
            } else {
                res.sendStatus(401);
            }
        } else {
            res.sendStatus(401);
        }
    } else if (req.body.stage === 2) {
        var authorizedHeaders = req.body;
        var token = authorizedHeaders.continueToken;
        var fetchedToken = await deleteMFA.get(token);
        if (!fetchedToken || fetchedToken.time < Date.now()) {
            return res.sendStatus(401);
        }
        let code = authorizedHeaders.code;
        let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
        if (doc) {
            if (await c.verifyPassword(req.body.password, doc.passwordHash)) {
                jwt.verify(req.token, process.env.KEY, async (err, authData) => {
                    if (err) return res.sendStatus(401);
                    else {
                        var token = n2fa.verifyToken(c.decrypt(doc.twoFactorCodeEncrypted, KEY, IV), code);
                        if (token) {
                            let hashedData = await c.hashPasswordSalt(authData.user.email, process.env.SALT);
                            profiles.deleteOne({ emailHash: hashedData });
                            users.deleteOne({ emailHash: hashedData }).then(() => res.status(200).send({})).catch(() => res.sendStatus(500));
                            res.cookie("token", "", { domain: ".nextflow.cloud", secure: true, expires: new Date(Date.now() + 1) });
                            await blacklist.create({
                                emailHash: hashedData,
                                tokenHash: await c.hashPasswordSalt(req.token, SALT_T)
                            });
                        } else {
                            if (doc.twoFactorBackupCodesHashed.findIndex(r => c.verifyPassword(code, r) === true) !== -1) {
                                let index = doc.twoFactorBackupCodesHashed.findIndex(r => c.verifyPassword(code, r) === true);
                                let authenticatedCode = doc.twoFactorBackupCodesHashed[index];
                                if (c.verify(authenticatedCode, doc.twoFactorBackupCodesSignature[index], SERVER_PUBLIC_KEY)) {
                                    let hashedData = await c.hashPasswordSalt(authData.user.email, process.env.SALT);
                                    profiles.deleteOne({ emailHash: hashedData });
                                    users.deleteOne({ emailHash: hashedData }).then(() => res.status(200).send({})).catch(() => res.sendStatus(500));
                                    await blacklist.create({
                                        emailHash: hashedData,
                                        tokenHash: await c.hashPasswordSalt(req.token, SALT_T)
                                    });
                                    res.cookie("token", "", { domain: ".nextflow.cloud", secure: true, expires: new Date(Date.now() + 1) });
                                } else {
                                    res.sendStatus(500);
                                }
                            } else {
                                res.sendStatus(401);
                            }
                        }
                    }
                });
            } else {
                res.sendStatus(401);
            }
        } else {
            res.sendStatus(401);
        }
    }
});

app.get("/ip", async (req, res) => {
    var ip = (req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress;
    res.send({ ip });
});

app.get("/user/:id?/username", verifyAuthToken, async (req, res) => {
    if (req.params.id) {
        let doc = await users.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
        if (doc) {
            res.send({ username: c.decrypt(doc.usernameEncrypted, KEY) });
        } else {
            res.status(409).send("User does not exist.");
        }
    } else {
        jwt.verify(req.token, process.env.KEY, async (err, authData) => {
            if (err) return res.sendStatus(401);
            res.status(200).send({ username: authData.user.username });
        });
    }
});

app.get("/user/token", async (req, res) => {
    if (req.cookies.token) {
        res.send({ token: req.cookies.token });
    } else {
        res.send({ token: null });
    }
});

app.get("/user/id", verifyAuthToken, async (req, res) => {
    let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (doc) {
        res.send({ id: c.decrypt(doc.idEncrypted, KEY) });
    } else {
        res.send({ id: null });
    }
});

app.patch("/user/email-visible", verifyAuthToken, async (req, res) => {
    let prof = await profiles.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
    if (prof) {
        let previousV = false;
        if (c.decrypt(prof.emailPublic, KEY) === "true" && c.verify(prof.emailPublic, prof.emailPublicSignature, SERVER_PUBLIC_KEY)) {
            previousV = true;
        }
        let currentV = previousV ? false : true;
        let newV = c.encrypt(currentV.toString(), KEY);
        let newVSigned = c.sign(newV, SERVER_PRIVATE_KEY);
        await profiles.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }, { emailPublic: newV, emailPublicSignature: newVSigned });
        res.sendStatus(204);
    } else {
        res.send("You don't exist.");
    }
});

app.patch("/user/description", verifyAuthToken, async (req, res) => {
    let desc = req.body.description;
    let descEncrypted = c.encrypt(desc, KEY);
    await profiles.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }, { descriptionEncrypted: descEncrypted });
    res.send("Set description!");
});

app.patch("/user/website", verifyAuthToken, async (req, res) => {
    let website = req.body.website;
    let websiteEncrypted = c.encrypt(website, KEY);
    await profiles.findOneAndUpdate({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) }, { websiteEncrypted });
    res.send("Set website!");
});

app.get("/user/:id?", verifyAuthToken, async (req, res) => {
    let userObj = {};
    if (req.params.id) {
        let doc = await users.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
        let prof = await profiles.findOne({ idHash: await c.hashPasswordSalt(req.params.id, process.env.SALT) });
        if (doc) {
            let tmpemail = "";
            if (c.decrypt(prof.emailPublic, KEY) === "true" && c.verify(prof.emailPublic, prof.emailPublicSignature, SERVER_PUBLIC_KEY)) {
                tmpemail = c.decrypt(prof.emailEncrypted, KEY);
            }
            let emailAvailable = false;
            if (c.decrypt(prof.emailPublic, KEY) === "true" && c.verify(prof.emailPublic, prof.emailPublicSignature, SERVER_PUBLIC_KEY)) {
                emailAvailable = true;
            }
            userObj.username = c.decrypt(doc.usernameEncrypted, KEY);
            userObj.id = req.params.id;
            userObj.emailAvailable = emailAvailable;
            userObj.email = tmpemail;
            userObj.website = c.decrypt(prof.websiteEncrypted, KEY);
            userObj.description = c.decrypt(prof.descriptionEncrypted, KEY);
            userObj.avatar = `https://secure.nextflow.cloud/api/user/${req.params.id}/avatar`;
            res.send(userObj);
        } else {
            res.status(409).send("User does not exist.");
        }
    } else {
        let doc = await users.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
        let prof = await profiles.findOne({ emailHash: await c.hashPasswordSalt(req.email, process.env.SALT) });
        if (prof) {
            let emailAvailable = false;
            if (c.decrypt(prof.emailPublic, KEY) === "true" && c.verify(prof.emailPublic, prof.emailPublicSignature, SERVER_PUBLIC_KEY)) {
                emailAvailable = true;
            }
            userObj.username = c.decrypt(doc.usernameEncrypted, KEY);
            userObj.id = c.decrypt(doc.idEncrypted, KEY);
            userObj.emailAvailable = emailAvailable;
            userObj.email = req.email;
            userObj.website = c.decrypt(prof.websiteEncrypted, KEY);
            userObj.description = c.decrypt(prof.descriptionEncrypted, KEY);
            userObj.avatar = `https://secure.nextflow.cloud/api/user/${c.decrypt(doc.idEncrypted, KEY)}/avatar`;
            userObj.privateAvatar = `https://secure.nextflow.cloud/api/user/avatar`;
            res.send(userObj);
        } else {
            res.status(409).send("You don't exist.");
        }
    }
});

app.post("/logout", verifyAuthToken, async (req, res) => {
    res.cookie("token", "", { domain: ".nextflow.cloud", secure: true, expires: new Date(Date.now() + 1) });
    await blacklist.create({
        emailHash: await c.hashPasswordSalt(req.email, process.env.SALT),
        tokenHash: await c.hashPasswordSalt(req.token, SALT_T)
    });
    res.status(200).send("Logged out!");
});

app.all("/*", (req, res) => {
    res.status(404).send("Could not find the page, requested on the API.");
});

export default app;
