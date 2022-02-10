const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require("cors");
const dotenv = require('dotenv');
dotenv.config();
const Database = require("./classes/ExpressDB");
const crypto = require('./classes/Crypto.js');
const blacklist = require('./models/blacklist.js');
const database = new Database(process.env.URI, process.env.DB);
database.on("connected", () => console.log("connected to database"));
database.connect();
const forgotPasswords = require("./models/forgotPasswords");

var whitelist = ['https://secure.nextflow.cloud', 'https://chat.nextflow.cloud', 'https://ss.nextflow.cloud', 'http://localhost:3001', 'https://test.nextflow.cloud'];
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
// app.use('/api', cors(corsOptions));
// app.use('/api', verifyAuthToken);
// app.use('/api', (req, res, next) => {
//    res.status(451).send('<h1>451</h1><h2>Unavailable for legal reasons</h2><h2>由于法律原因不可用</h2><div><p><b>What does this mean?</b></p><p>Nextflow services are unavailable in China. If you reside in China, you cannot access this service due to legal restrictions. If you are not in China, please contact us.</p></div><div><p><b>这是什么意思？</b></p><p>Nextflow服务在中国不可用。如果您居住在中国，由于法律限制，您将无法访问此服务。如果您不在中国，请与我们联系。</p></div>');
//    res.send("yo @queryzi");
//    next(req, res)
// });

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
app.listen(3000, async () => {
    console.log('Ready!')
});
