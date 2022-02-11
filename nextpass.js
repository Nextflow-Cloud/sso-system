import express from "express";
const app = express.Router(); 

import jwt from "jsonwebtoken";
import upload from "express-fileupload";

import c from "./classes/Crypto.js";

import { verifyAuthToken } from "./functions.js";

app.use(upload());

app.get('/db/hash', verifyAuthToken, async (req, res) => {
    let id;
    jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
        if (err) {
            res.sendStatus(403);
        } else {
            id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT)
            fs.access('./cached_db/' + id + 'PWD_DB_HASH', fs.constants.F_OK, (err) => {
                if (err) {
                    res.status(417).send('You do not have a database, please create one.');
                    return
                }

                res.download('./cached_db/' + id + 'PWD_DB_HASH', 'PWD_DB_HASH');
            })
        };
    });
});

app.get('/db', verifyAuthToken, async (req, res) => {
    let id;
    jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
        if (err) {
            res.sendStatus(403);
        } else {
            id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT)
            fs.access('./cached_db/' + id + 'pwd.db.encrypted', fs.constants.F_OK, (err) => {
                if (err) {
                    res.status(417).send('You do not have a database, please create one.');
                    return
                }

                res.download('./cached_db/' + id + 'pwd.db.encrypted', 'pwd.db.encrypted');
            })
        };
    });
});

app.post('/db/hash', verifyAuthToken, async (req, res) => {
    if (req.files) {
        var file = req.files.db_backup
        if (file) {
            var filename = file.name
            if (!filename === 'PWD_HASH') return res.sendStatus(403);
            let id;
            jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
                if (err) {
                    res.sendStatus(403);
                } else {
                    id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT)
                    file.mv('./cached_db/'+id+filename, function (err) {
                        if (err) {
                            res.status(500).send('error occured whoopos');
                        } else {
                            res.send('Cached succesfully!')
                        }
                    })
                };
            });
        } else {
            res.send('Invalid240124873184').status(400);
        }
    } else {
        res.send('Invalid1').status(400);
    }
});

app.post('/db', verifyAuthToken, async (req, res) => {
    if (req.files) {
        var file = req.files.db_backup
        if (file) {
            var filename = file.name
            if (!filename === 'pwd.db.encrypted') return res.sendStatus(403);
            let id;
            jwt.verify(JSON.parse(req.headers.authorization).token, process.env.KEY, async (err, authData) => {
                if (err) {
                    res.sendStatus(403);
                } else {
                    id = await c.hashPasswordSalt(JSON.parse(req.headers.authorization).token + authData.user.email, process.env.SALT)
                    file.mv('./cached_db/'+id+filename, function (err) {
                        if (err) {
                            res.status(500).send('error occured whoops');
                        } else {
                            res.send('Cached succesfully!')
                        }
                    })
                };
            });
        } else {
            res.send('Invalid2').status(400);
        }
    } else {
        res.send('Invalid1').status(400);
    }
});

export default app;
