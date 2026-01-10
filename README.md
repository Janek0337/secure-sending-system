# Secure Sending System
This is one of the systems that will allow you to send securely encrpted mesages and attachments between you and your friends.
The project's motto is "Mind the hooks, not the looks".
# Core features
- send message to at least one receiver
- add up to 25 MB of attachments to your message
- mark as read or delete received messages
- verify message's authenticity with signed hashes by sender's key
- account access protected with two-factor authentication using TOTP codes <br> it is advised to prepare an app to handle your secret e.g. Ente Auth
# Installation and deployment
1. Deploy server:<br>
This instructions will allow you to deploy application's server with docker at port 5000:
   - clone repository:
   `git clone https://github.com/Janek0337/secure-sending-system`
   - Go to repo's directory: `cd secure-sending-system`
   - rename file `server/.env.example` to `server/.env` and fill both keys for server to use (base64)
   - grant running access to the starting script: `sudo chmod +x ./run-docker.sh`
   - run the script: `./run-docker.sh`<br><br>
2. Install client:<br>
Assuming you already have uv installed:
   - clone repository:
      `git clone https://github.com/Janek0337/secure-sending-system`
   - Go to repo's directory: `cd secure-sending-system`
   - install dependencies: `uv sync --package client`
   - grant running access to the starting script: `sudo chmod +x ./run-client.sh` (skip this step on Windows)
   - run script with one argument pointing to server address: \<address:port\> e.g. `./run-client.sh 127.0.0.1:5000` (or `./run-clientw.ps1 127.0.0.1:5000` on Windows)
   - the client application will be accessible at 127.0.0.1:3045 (type it in your browser's address bar and continue from there on)