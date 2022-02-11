import express from "express";
const app = express();

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

import forgotPasswords from "./models/forgotPasswords.js"; // let's not forget to add .js because es modules are weird

import api from "./api.js";
import nextpass from "./nextpass.js";

import { changePassword, forgot } from "./html.js";

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

app.use("/api", api);
app.use("/api/nextpass", nextpass);
app.use('/', express.static(path.join(__dirname, 'webpack')));

// app.use('/api', (req, res, next) => {
//    res.status(451).send('<h1>451</h1><h2>Unavailable for legal reasons</h2><h2>由于法律原因不可用</h2><div><p><b>What does this mean?</b></p><p>Nextflow services are unavailable in China. If you reside in China, you cannot access this service due to legal restrictions. If you are not in China, please contact us.</p></div><div><p><b>这是什么意思？</b></p><p>Nextflow服务在中国不可用。如果您居住在中国，由于法律限制，您将无法访问此服务。如果您不在中国，请与我们联系。</p></div>');
//    res.send("yo @queryzi");
//    next(req, res)
// });

app.get('/change_password', async (req, res) => {
    res.send(changePassword);
});

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

app.listen(3000, () => console.enhancedLog("Express", 'Ready! Listening on port 3000 🚀')); // 3000, 3005
