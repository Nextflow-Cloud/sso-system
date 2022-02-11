import { Auth } from "googleapis";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

import Crypto from "./classes/Crypto.js";

import blacklist from "./models/blacklist.js";

export const createTransport = async () => {
    const oauth2Client = new Auth.OAuth2Client(process.env.CLIENT_ID, process.env.CLIENT_SECRET, "https://developers.google.com/oauthplayground");
    oauth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
    const accessToken = await new Promise((resolve, reject) => {
        oauth2Client.getAccessToken((err, token) => {
            if (err) reject("Failed to create access token :(");
            else resolve(token);
        });
    });
    const transporter = nodemailer.createTransport({
        service: "gmail",
        port: 587,
        secure: true,
        auth: {
            type: "OAuth2",
            user: process.env.USERNAME,
            accessToken,
            clientId: process.env.CLIENT_ID,
            clientSecret: process.env.CLIENT_SECRET,
            refreshToken: process.env.REFRESH_TOKEN
        }
    });
    return transporter;
};

export const verifyAuthToken = (req, res, next) => {
    const tokenHeader = req.headers.authorization;
    if (typeof tokenHeader !== "undefined") {
        let bearerToken;
        try {
            // backwards compatibility
            bearerToken = JSON.parse(tokenHeader).token;
        } catch (e) {
            bearerToken = tokenHeader.split("Bearer ")[1];
        }
        req.token = bearerToken;
        jwt.verify(req.token, process.env.KEY, async (err, authData) => {
            if (err) {
                console.error(err);
                res.status(401).send("Token is invalid or has expired");
            } else {
                req.email = authData.user.email;
                let doc = await blacklist.findOne({ emailHash: await Crypto.hashPasswordSalt(authData.user.email, process.env.SALT), tokenHash: await Crypto.hashPasswordSalt(req.token, process.env.SALT_T) });
                if (doc) {
                    res.status(401).send("Token has been invalidated");
                } else {
                    req.username = authData.user.username;
                    req.id = authData.user.id;
                    next();
                }
            };
        });
    } else {
        res.status(401).send("Token not provided");
    }
};
