const express = require('express');
const app = express();
const util = require('tweetnacl-util');
const nacl = require('tweetnacl');
const jwt = require('jsonwebtoken');
const cors = require("cors");
const dotenv = require('dotenv');
dotenv.config();
const KEY = util.decodeBase64(process.env.KEY);
const SERVER_PRIVATE_KEY = process.env.PRIVATE;
const SERVER_PUBLIC_KEY = process.env.PUBLIC;
const IV = util.decodeBase64(process.env.IV);
const Database = require("./classes/ExpressDB");
const crypto = require('./classes/Crypto.js');
const blacklist = require('./models/blacklist.js'); // see you never mongoose :D
const upload = require("express-fileupload");
const database = new Database(process.env.URI, process.env.DB);
database.on("connected", () => console.log("connected to database"));
database.connect();
const forgotPasswords = require("./models/forgotPasswords");

var whitelist = ['https://secure.nextflow.cloud', 'https://chat.nextflow.cloud', 'https://ss.nextflow.cloud', 'http://localhost:3001'];
var corsOptions = {
    origin: function (origin, callback) {
        if (whitelist.indexOf(origin) !== -1) {
            callback(null, true)
        } else {
            callback(new Error('Not allowed by CORS'))
        }
    }
};
const rateLimit = require('express-rate-limit');
const apiLimiter = rateLimit({
	windowMs: 5 * 60 * 1000,
	max: 60,
	standardHeaders: true, 
	legacyHeaders: false, 
});
app.use('/api', apiLimiter);

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
                let doc = await blacklist.findOne({ emailHash: await crypto.hashPasswordSalt(authData.user.email, process.env.SALT), tokenHash: await crypto.hashPasswordSalt(req.token, process.env.SALT_T) });
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
    };
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }))
app.use(upload());
app.use(cors());

app.get('/change_password', async (req, res) => {
    res.send(require("./html").changePassword);
});

app.get('/forgot/:code', async (req, res) => {
    let doc = await forgotPasswords.findOne({ idHash: await crypto.hashPasswordSalt(req.params.code, process.env.SALT) });
    if (doc) {
        res.send(require("./html").forgot.replace(/{req.params.code}/g, req.params.code)); 
    } else {
        res.sendStatus(401);
    }
});
app.use("/api", require("./api"));
app.use("/api/nextpass", require("./nextpass"));
app.use('/', express.static((require("path")).join(__dirname, 'webpack')));
app.get('*', (req, res) => {
    res.sendFile((require("path")).join(__dirname, 'webpack/index.html'));
});
app.listen(3000, async () => console.log('Ready!'));
