import jwt from 'jsonwebtoken';
import moment from 'moment';
import NodeRsa from 'node-rsa';
import crypto from 'crypto';

// const encryption = require('../server');
// console.log(encryption)

import { Client } from '../models/Client';



/**
 *
 */
const register = async (req, res) => {

  const { email, password, name } = req.body;

  let client = await Client.findOne({ email });

  if(client) {
    console.log(client);
    console.log(`Account under ${email} already exists!`);
    return res.status(409).send({message: `Account under ${email} already exists!`});
  }

  client = new Client({email, name});
  client.password = client.hash(password);
  client.clientKey = generateClientKey(client.password, req.app.get('encryption'));

  // DEBUG: Just logging this out so i can use it in postman
  console.log(`DEBUG: ${email}'s encrypted password with it's client key:`);
  encrypt(password, req.app.get('encryption'), client.clientKey);


  try {
    client.save();
    console.log(`${email} added`);
    res.send({message: `Account for ${email} successfully created`, clientKey: client.clientKey})
  } catch (error) {
    console.log(error);
    res.status(500).send({message: error});
  }
};

const login = async (req, res) => {
  const { email } = req.query;
  const { encrypted } = req.body;

  const client = await Client.findOne({email});
  if(!client) {
    console.error(`No client registered with ${email}`);
    return res.status(401).send({message: `No client registered with ${email}`});
  }

  const password = decrypt(encrypted, req.app.get('encryption'), client.clientKey);

  if(!client.isValidPassword(password)) {
    return res.status(403).send({message: `Incorrect password supplied for ${email}`})
  }

  res.send("logged in!")

};


function generateClientKey(data, encryption) {

  const { algorithm, generationKey, plainEncoding, encryptedEncoding} = encryption;
  const cipher = crypto.createCipher(algorithm, generationKey);
  let ciphered = cipher.update(data, plainEncoding, encryptedEncoding);
  ciphered += cipher.final(encryptedEncoding);
  console.log(`Generated client key: ${ciphered}`);

  return ciphered;
}

function encrypt(data, encryption, key) {
  const { algorithm,  plainEncoding, encryptedEncoding} = encryption;
  const cipher = crypto.createCipher(algorithm, key);
  let ciphered = cipher.update(data, plainEncoding, encryptedEncoding);
  ciphered += cipher.final(encryptedEncoding);
  console.log(`Encrypted ${data}: ${ciphered}`);

  return ciphered;
}

function decrypt(data, encryption, expectedKey) {
  const { algorithm, generationKey, plainEncoding, encryptedEncoding} = encryption;

  const decipher = crypto.createDecipher(algorithm, expectedKey);
  let deciphered = decipher.update(data, encryptedEncoding, plainEncoding);
  deciphered += decipher.final(plainEncoding);
  console.log(`Decrypted ${data}: ${deciphered}`);

  return deciphered
}

module.exports = {
  register,
  login
};


