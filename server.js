const express = require("express");
require('dotenv').config();
const app = express();
const fs = require('fs');
const jwt = require("jsonwebtoken"); //  couldn't use this in CF worker :p
const crypto = require("crypto"); // couldn't use createPrivateKey/createPublicKey in CF worker :p
app.use(express.json());

app.get("/", function(request, response) {
  response.send("Hello there!");
});

app.post("/snowflake-auth", function (request, response) {
  
  const {key, accountIdentifier, user } = request.body;
  //let privateKeyFile = fs.readFileSync(`./test_keys/${key}.p8`);  // read rsa key file
  let privateKeyEnv = process.env[key] || "";
  let privateKeyObject = crypto.createPrivateKey({ key: privateKeyEnv, format: 'pem' });
  let privateKey = privateKeyObject.export({ format: 'pem', type: 'pkcs8' }); // convert key to pkcs8 pem format

  let publicKeyObject = crypto.createPublicKey({ key: privateKey, format: 'pem' });
  let publicKey = publicKeyObject.export({ format: 'der', type: 'spki' });
  let publicKeyFingerprint = 'SHA256:' + crypto.createHash('sha256') .update(publicKey, 'utf8') .digest('base64'); // get pub finger print

  let payload =  {
    "exp":  Math.floor(Date.now() / 1000) + (60 * 60),
    "iss": `${accountIdentifier}.${user}.${publicKeyFingerprint}`,
    "sub": `${accountIdentifier}.${user}`
  }
  let token = jwt.sign(payload,  privateKey, {algorithm:'RS256'}); // create jwt
  response.json({ token });
});

// listen for requests :)
const listener = app.listen(3000, function () {
  console.log("Your app is listening on port " + listener.address().port);
});
