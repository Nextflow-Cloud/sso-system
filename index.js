import express from "express";
const app = express();

import favicon from "serve-favicon";
import cors from "cors";
import { rateLimit } from "express-rate-limit";

import dotenv from "dotenv";
dotenv.config();

import path from "path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import Database from "./classes/ExpressDB.js";
import Crypto from "./classes/Crypto.js";
import Logger from "./classes/Logger.js";

import forgotPasswords from "./models/forgotPasswords.js";

import api from "./api.js";
import nextpass from "./nextpass.js";

import { changePassword, forgot, chineseBlock } from "./html.js";
import geoip from "geoip-lite";

const database = new Database(process.env.URI, process.env.DB);
database.on("connected", () => {
    console.log("Connected to database");
    // Initiate our custom Logger when the database is connected.
    database.logger = new Logger();
});
await database.connect();

// var whitelist = ['https://secure.nextflow.cloud', 'https://chat.nextflow.cloud', 'https://ss.nextflow.cloud', 'http://localhost:3001', 'https://test.nextflow.cloud'];
// var corsOptions = {
//     origin: function (origin, callback) {
//         if (whitelist.indexOf(origin) !== -1) {
//             callback(null, true)
//         } else {
//             callback(new Error('Not allowed by CORS'))
//         }
//     }
// };

app.use((req, res, next) => {
    res.setHeader('X-Powered-By','Nextflow Technologies')
    next();
})
app.use(favicon(path.join(__dirname, 'public', 'icons', 'favicon.ico')))
app.use(cors());
// app.use('/api', cors(corsOptions));
app.use('/api', rateLimit({
	windowMs: 5 * 60 * 1000,
	max: 60,
	standardHeaders: true, 
	legacyHeaders: false, 
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', (req, res, next) => {
    var ip = (req.headers["x-forwarded-for"] || "").split(",").pop().trim() || req.socket.remoteAddress;
    if (geoip.lookup(ip).country == 'CN') {
        app.set('title', 'Blocked due to legal restrictions')
        res.status(451).send(chineseBlock)
    } else {
        next()
    }
});

app.use("/api/nextpass", nextpass);
app.use("/api", api);
app.use('/', express.static(path.join(__dirname, 'webpack')));


app.get('/change_password', async (req, res) => {
    res.send(changePassword);
});

app.get('/chinese_block', async (req, res) => {
    res.status(451).send(chineseBlock)
})

app.get('/forgot/:code', async (req, res) => {
    let doc = await forgotPasswords.findOne({ idHash: await Crypto.hashPasswordSalt(req.params.code, process.env.SALT) });
    if (doc) {
        res.send(forgot.replace(/{req.params.code}/g, req.params.code)); 
    } else {
        res.sendStatus(401);
    }
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'webpack/index.html'));
});

app.listen(3000, () => console.enhancedLog("Express", 'Ready! Listening on port 3000 🚀')); // 3001, 3005
