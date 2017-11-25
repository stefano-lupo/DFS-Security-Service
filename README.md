# Security (Kerberos)
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
	- **Is there any way of encrypting the email too - but then how does server know which key to decrypt with - JWT?**

3. Once the AS has authenticated the client the Kerberos process can begin.
	- AS generates a (finite lifespan) session key `Sk`.
	- AS then creates a token that contains the following:
		- An unencrypted copy of `Sk` - (for the client)
		- A copy of `Sk` encrypted with the ***secret*** (known to all servers) server key `Ks` - (for the other servers)
	- This entire token is then encrypted using the Client Key `Kc` protecting it from eavesdropper's.

4. This token then arrives at the Client who can decrypt it using the Client Key `Kc`.
	- The client can now has access to the session key `Sk`.
	- The client can now send the following to any server to prove their identity.
		- The message they want to send (encrypted with `Sk`)
		- The copy of `Sk` encrypted with `Ks` that they received from the AS.
			- This can be decrypted by all servers (who have copies of `Ks`), giving the servers access to `Sk`.
			- Thus the servers can then decrypt the client's message with the perishable session key `Sk`.