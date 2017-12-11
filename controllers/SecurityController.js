import moment from 'moment';
import crypto from 'crypto';
import { Client } from '../models/Client';


/********************************************************************************************************
 * Client API
 *******************************************************************************************************/


/**
 * POST /register
 * body: {email, password (unencrypted), name}
 * @response: (successful) -> {message, clientKey}
 */
export const register = async (req, res) => {

  const { email, password, name } = req.body;

  // Ensure client doesnt already exist
  let client = await Client.findOne({ email });
  if(client) {
    console.log(`Account under ${email} already exists!`);
    return res.status(409).send({message: `Account under ${email} already exists!`});
  }

  // Create clients account
  client = new Client({email, name});
  client.password = client.hash(password);

  // Generate the symmetric client key using the clients hashed password and save it
  client.clientKey = generateClientKey(client.password, req.app.get('encryption'));

  try {
    client.save();
    console.log(`${email} added`);

    // Send the client the symmetric key
    // This is used for all subsequent comms with security service (for logging in)
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
export const login = async (req, res) => {
  const { email } = req.query;
  const { encrypted } = req.body;

  const client = await Client.findOne({email});
  if(!client) {
    console.error(`No client registered with ${email}`);
    return res.status(401).send({message: `No client registered with ${email}`});
  }

  // Decrypt their password using the symmetric clientKey
  const encryption = req.app.get('encryption');

  let password;
  try {
    password = decrypt(encrypted, encryption, client.clientKey);
  } catch (err) {
    console.error(`Couldnt decrpyt password: ${err}`);
    return res.status(403).send({message: `Invalid client key used for encryption`});
  }

  // Check the password matches with our hash of their password
  if(!client.isValidPassword(password)) {
    return res.status(403).send({message: `Incorrect password supplied for ${email}`})
  }


  // Create a random session key that the client can use to encrypt their traffic to other servers
  // Essentially building a (changeable) symmetric key between client and our servers
  const sessionKey = crypto.randomBytes(48).toString('hex');


  // Generate ticket for our servers to decrypt
  // This can contain any useful information we may need
  let ticket = JSON.stringify({
    _id: client._id,
    expires: moment().add(encryption.ticketExpiry, 'h'), // also means tickets aren't always same
    sessionKey,
  });


  // The token contains a copy of the sessionKey (for the clients use)
  // and an encrypted (with key known to all servers) version of the ticket (for server use)
  const token = {
    sessionKey,
    ticket: encrypt(ticket, encryption, encryption.serverKey)
  };

  res.send({message: `Successfully logged in`, token: encrypt(JSON.stringify(token), encryption, client.clientKey)});
};


/********************************************************************************************************
 * Inter Service API
 *******************************************************************************************************/

/**
 * Get /client/:email
 * Gets client's _id associated with an email
 * This allows clients to query public files that other users have by the other users email
 * The directory service then hits this endpoint to get the relevant _id of that user
 */
export const getClientByEmail = async (req, res) => {
  const { email } = req.params;
  const client = await Client.findOne({email});

  if(!client) {
    return res.status(404).send({message: `No client with email ${email} has registered`});
  }

  res.send({_id: client._id});
};


/********************************************************************************************************
 * Helper Methods
 *******************************************************************************************************/

/**
 * Generates a client key on registration that will be used as a symmetric key
 * for communication between the client and this service (client encrypts login requests with this key).
 * This client key is the passed in data (eg hash of password) encrypted with the specified encryption
 * scheme and the GENERATION_KEY known only to this service.
 * @param data to be encypted
 * @param encryption scheme to be used
 */
function generateClientKey(data, encryption) {
  const { algorithm, generationKey, plainEncoding, encryptedEncoding} = encryption;
  const cipher = crypto.createCipher(algorithm, generationKey);
  let ciphered = cipher.update(data, plainEncoding, encryptedEncoding);
  ciphered += cipher.final(encryptedEncoding);

  return ciphered;
}

/**
 * Encrypts some data using the given encryption parameters and secret key
 * @param data string to be encrypted
 * @param encryption schema to be used for encryption
 * @param key the secret key to use for the encryption
 */
function encrypt(data, encryption, key) {
  const { algorithm,  plainEncoding, encryptedEncoding} = encryption;
  const cipher = crypto.createCipher(algorithm, key);
  let ciphered = cipher.update(data, plainEncoding, encryptedEncoding);
  ciphered += cipher.final(encryptedEncoding);

  return ciphered;
}

/**
 * Decrypts some data using the encryption key and expected key
 * @param data to be decrypted
 * @param encryption scheme being used
 * @param expectedKey the key that the data should have been encrypted with
 */
function decrypt(data, encryption, expectedKey) {
  const { algorithm, plainEncoding, encryptedEncoding} = encryption;

  const decipher = crypto.createDecipher(algorithm, expectedKey);
  let deciphered = decipher.update(data, encryptedEncoding, plainEncoding);
  deciphered += decipher.final(plainEncoding);

  return deciphered
}

