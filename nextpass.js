import express from "express";
const app = express.Router(); 

import jwt from "jsonwebtoken";
import upload from "express-fileupload";

import fs from "fs";

import c from "./classes/Crypto.js";

import { verifyAuthToken } from "./functions.js";

app.use(upload());

app.get("/db/hash", verifyAuthToken, async (req, res) => {
    jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
        if (err) {
            res.sendStatus(403);
        } else {
            var id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT);
            try {
                fs.accessSync("./cached_db/" + id + "PWD_DB_HASH", fs.constants.F_OK);
            } catch {
                res.status(417).send("You do not have a database, please create one.");
                return;
            }
            res.download("./cached_db/" + id + "PWD_DB_HASH", "PWD_DB_HASH");
        };
    });
});

app.get("/db", verifyAuthToken, async (req, res) => {
    jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
        if (err) {
            res.sendStatus(403);
        } else {
            var id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT);
            try {
                fs.accessSync("./cached_db/" + id + "pwd.db.encrypted", fs.constants.F_OK);
            } catch {
                res.status(417).send("You do not have a database, please create one.");
                return;
            }
            res.download("./cached_db/" + id + "pwd.db.encrypted", "pwd.db.encrypted");
        };
    });
});

app.post("/db/hash", verifyAuthToken, async (req, res) => {
    if (req.files && req.files.db_backup) {
        if (req.files.db_backup.name !== "PWD_HASH") return res.sendStatus(403);
        jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
            if (err) {
                res.sendStatus(403);
            } else {
                var id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT);
                req.files.db_backup.mv("./cached_db/" + id + req.files.db_backup.name, err => {
                    if (err) {
                        res.status(500).send("Whoops, an error occurred");
                    } else {
                        res.send("Cached successfully!");
                    }
                });
            }
        });
    } else {
        res.send("Invalid").status(400);
    }
});

app.post("/db", verifyAuthToken, async (req, res) => {
    if (req.files && req.files.db_backup) {
        if (req.files.db_backup.name !== "pwd.db.encrypted") return res.sendStatus(403);
        jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
            if (err) {
                res.sendStatus(403);
            } else {
                var id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT);
                req.files.db_backup.mv("./cached_db/" + id + req.files.db_backup.name, err => {
                    if (err) {
                        res.status(500).send("Whoops, an error occurred");
                    } else {
                        res.send("Cached successfully!");
                    }
                });
            };
        });
    } else {
        res.send("Invalid").status(400);
    }
});

export default app;
