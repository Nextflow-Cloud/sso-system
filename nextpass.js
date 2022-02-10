const express = require("express");
const app = express.Router(); 
const blacklist = require('./models/blacklist');
const c = require('./classes/Crypto');
const jwt = require('jsonwebtoken')
const upload = require("express-fileupload");

app.use(upload());

const verifyAuthToken = (req, res, next) => {
    const tokenHeader = req.headers.authorization;

    if (typeof tokenHeader !== 'undefined') {
        const bearer = JSON.parse(tokenHeader);

        const bearerToken = bearer.token;

        req.token = bearerToken;

        jwt.verify(req.token, process.env.KEY, async (err, authData) => {
            if (err) {
                res.sendStatus(403);
            } else {
                req.email = authData.user.email;
                let doc = await blacklist.findOne({ emailHash: await c.hashPasswordSalt(authData.user.email, process.env.SALT), tokenHash: await c.hashPasswordSalt(req.token, process.env.SALT_T) });
                if (doc) {
                    res.status(403).send('Forbidden, illegal token used.');
                } else {
                    req.username = authData.user.username;
                    req.id = authData.user.id;
                    next();
                }
            };
        });
    } else {
        res.status(403).send('Forbidden');
    }
};

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
    // console.log(req.headers);
    // console.log(req.body);
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
}); // dude wait wait wait wait wait 
// dude so how do you store another db
// if you already have a db in here
// bruh
// dude dude dude
// say someone creates a new vault
// then their new vault overwrites
// the old one!?!?!?!?!!?
// that is concerning
// wdym

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

module.exports = app;
