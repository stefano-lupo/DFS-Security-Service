import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import morgan from 'morgan';

// Initialize .env
import dotenv from 'dotenv';
dotenv.config();

const encryption = {
  algorithm: process.env.SYMMETRIC_ENCRYPTION,
  plainEncoding: process.env.PLAIN_ENCODING,
  encryptedEncoding: process.env.ENCRYPTED_ENCODING,
  ticketExpiry: process.env.TICKET_EXPIRY,
  generationKey: process.env.GENERATION_KEY,
  serverKey: process.env.SERVER_KEY
};

const port = process.argv[2] || process.env.PORT || 3003;

// Import Controllers
import * as SecurityController from './controllers/SecurityController';


const app = express();

// expose encryption variables to app
app.set('encryption', encryption);


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

// Inter service endpoints
app.get('/client/:email', SecurityController.getClientByEmail);



// Initialize the Server
app.listen(port, () => {
  console.log(`Security Service on port ${port}`);
});


