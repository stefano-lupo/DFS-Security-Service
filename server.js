// Initialize .env
require('dotenv').config();

const encryption = {
  algorithm: process.env.SYMMETRIC_ENCRYPTION,
  plainEncoding: process.env.PLAIN_ENCODING,
  encryptedEncoding: process.env.ENCRYPTED_ENCODING,
  ticketExpiry: process.env.TICKET_EXPIRY,
  generationKey: process.env.GENERATION_KEY,
  serverKey: process.env.SERVER_KEY
};
exports.encryption = encryption;

import express from 'express';
import mongoose from 'mongoose';


import bodyParser from 'body-parser';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';

// Import Controllers
import SecurityController from './controllers/SecurityController';

const app = express();




// Initialize the DB
const dbURL = "mongodb://localhost/dfs_clients";
mongoose.connect(dbURL);
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  console.log("Connected to Database");
});



app.use(bodyParser.urlencoded({extended: true}));   // Parses application/x-www-form-urlencoded for req.body
app.use(bodyParser.json());                         // Parses application/json for req.body
app.use(morgan('dev'));


// Note assuming this is done over HTTPS and thus safe
app.post('/register', SecurityController.register);

// Encrypted with clientKeys
app.post('/login', SecurityController.login);




// Debug endpoints
app.post('/verifyTicket', SecurityController.verifyTicket);



// expose environment variables to app
app.set('encryption', encryption);

// Initialize the Server
app.listen(3003, function() {
  console.log('Security Service on port 3003');
});


