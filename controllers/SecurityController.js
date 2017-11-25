import moment from 'moment';
import crypto from 'crypto';

// const encryption = require('../server');
// console.log(encryption)

import { Client } from '../models/Client';



/**
 * POST /register
 * body: {email, password (unencrypted), name}
 * @response: (successful) -> {message, clientKey}
 */
const register = async (req, res) => {

  const { email, password, name } = req.body;

  let client = await Client.findOne({ email });

  if(client) {
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

/**
 * POST /login?email=<email>
 * body: {encrypted: password (encrypted with client key)}
 */
const login = async (req, res) => {
  const { email } = req.query;
  const { encrypted } = req.body;

  const client = await Client.findOne({email});
  if(!client) {
    console.error(`No client registered with ${email}`);
    return res.status(401).send({message: `No client registered with ${email}`});
  }

  // Decrypt their password using the symmetric clientKey
  const encryption = req.app.get('encryption');
  const password = decrypt(encrypted, encryption, client.clientKey);

  // Check the password matches with our hash of their password
  if(!client.isValidPassword(password)) {
    return res.status(403).send({message: `Incorrect password supplied for ${email}`})
  }


  // Create a random session key that the client can use to encrypt their traffic to other servers
  // Essentially building a (changeable) symmetric key between client and our servers
  const sessionKey = crypto.randomBytes(48).toString('hex');


  // TODO: Ensure that this is safe (allows us to extract useful info (clients id) AND verify them)
  // Generate ticket for our servers to decrypt
  // This can contain any useful information we may need
  let ticket = JSON.stringify({
    _id: client._id,
    expires: moment().add('1h'),
    sessionKey,
    // noise: crypto.randomBytes(48).toString('hex')   // salt so tickets not always same - done by expires now
  });


  // The token contains a copy of the sessionKey (for the clients use)
  // and an encrypted (with commonly know server key) version of the ticket (for server use)
  const token = {
    sessionKey,
    ticket: encrypt(ticket, encryption, encryption.serverKey)
  };

  res.send({message: `Successfully logged in`, token: encrypt(JSON.stringify(token), encryption, client.clientKey)});
};


/**
 * This is just for debugging
 * POST /verifyTicket
 * body: {ticket}
 */
const verifyTicket = async (req, res) => {
  const encryption = req.app.get('encryption');
  const { ticket } = req.body;
  console.log(`Verifying ticket: ${ticket}`);
  const decryptedString = decrypt(ticket, encryption, encryption.serverKey);

  try {
    const decrypted = JSON.parse(decryptedString);
    console.log(`Successfully decrypted: ${JSON.stringify(decrypted)}`);
    res.send(decrypted);
  } catch (err) {
    console.error(err);
    res.status(400).send("Could not decrypt - token invalid");
  }

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
  login,
  verifyTicket
};


