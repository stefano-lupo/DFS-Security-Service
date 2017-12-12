# Distributed File System: Security Service
This repo contains the code for security service for my distributed file system. Links to all components of my file system can be found in the repo for the [test client and client library](https://github.com/stefano-lupo/DFS-Client)

## The Security Service
The Security Service is the first thing that clients must interact with in order to use the distributed file system. It provides a way for clients to authenticate themselves when communicating with other services and for the client's themselves to ensure that they are in fact communicating with a legitimate service (and not a fake). This is done using a system very similar to Kerberos.

The security service itself contains a mongoDB collection of Clients. For each client, the following is stored:
- name
- email
- password (hashed)
- lastLogIn
- clientKey (also hashed)

Of interest here is the clientKey. This is a symetric key that is unique for each client that registers with the security service. It is used to encrypt subsequent login requests from the client. 

Upon successful authentication, the client is provided with a token which contains a key to encrypt all messages to other servers with, and an encrtypted piece of data which is to be used as the `Authorization` header for all requests to the distributed file system's servers.

## Kerberos Implementation
The mechanism for authenticating a client and providing them with secure access to the file system is the following:
	
1. Client registers by sending: name, email and password (assume over HTTPS or something secure).
	- AS then generates a client key (`Kc`) for that client using:
		- The client's hashed password (which is stored in the database).
		- A key for generating client keys (GENERATION_KEY - in .env file).
	- The server sends `Kc` back to the client who saves it (again over HTTPS or something).
	- We now have a symmetric key for each client who registers.
	- This can be used to encrypt subsequent login requests over HTTP.

2. The client can then login by sending: email (as query param), password (encrypted with `Kc`)
	- The AS can then lookup that client (by email) and pull out the expected Client Key `Kc`.
	- It can then use that to decrypt the client's (plaintext) password.
		- This password can then be hashed and compared with the hash stored in the database, allowing the client to be authenticated.
		
3. Once the AS has authenticated the client the Kerberos process can begin.
	- AS generates a (finite lifespan) session key `Sk`.
	- AS then creates a token that contains the following:
		- An unencrypted copy of `Sk` (for the client)
		- A copy of `Sk` encrypted with the ***secret*** (known to all servers) server key `Ks` (for the other servers)
	- This entire token is then encrypted using the Client Key `Kc` protecting it from eavesdropper's.

4. This token then arrives at the Client who can decrypt it using the Client Key `Kc`.
	- The client can now has access to the session key `Sk`.
	- The client can now send the following to any server to prove their identity.
		- The message they want to send (encrypted with `Sk`)
		- The copy of `Sk` encrypted with `Ks` that they received from the AS.
			- This can be decrypted by all servers (who have copies of `Ks`), giving the servers access to `Sk`.
			- Thus the servers can then decrypt the client's message with the perishable session key `Sk`.

Using this system, the server's can be sure that the client is fully authenticated by the security service and the client can be sure that only legitimate servers can decrypt the contents of the messages it sends (as they have the secret `Ks`).


## Client API
#### `POST /register`
- **body**
	- `email`: the email address of the client who is registering
	- `password`: the password the client would like to register with
	- `name`: the name of the client
- Note that it is assumed this is done using some secure method.
- Registers the client with the security service.
- If the registration process is successful, the security service will respond with the client's clientKey `Kc`
	- This must be saved by the client and used to encrypt subsequent login requests.


#### `POST /login/?email=<email>`
- **body**
	- `encrypted`: the client's password encrypted with the client's key `Kc`
- Attempts to log the client in to the Security Service.
- If the login is successful, the Security Service will respond with a token (encrypted with `Kc`) as defined above.
- This token must be decrypted and the contents used to authenticate the client with all other services as discussed above.

## Inter Service API
#### `GET /client/:email`
- Get's the `_id` of the client who has the corresponding email address.
- This is used by the directory service in order to allow users to request the public files of other users by `email`. 






