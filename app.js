const express = require('express');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = 3000;

AWS.config.update({ region: 'eu-west-3' });
const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

function calculateSecretHash(username) {
    return crypto.createHmac('sha256', CLIENT_SECRET)
        .update(username + CLIENT_ID)
        .digest('base64');
}

app.use(bodyParser.json());

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Nom d\'utilisateur et mot de passe requis.' });
    }

    const params = {
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: CLIENT_ID,
        AuthParameters: {
            USERNAME: username,
            PASSWORD: password,
            SECRET_HASH: calculateSecretHash(username),
        },
    };

    try {
        const response = await cognitoIdentityServiceProvider.initiateAuth(params).promise();
        return res.status(200).json({
            message: 'Connexion réussie',
            accessToken: response.AuthenticationResult.AccessToken,
            idToken: response.AuthenticationResult.IdToken,
            refreshToken: response.AuthenticationResult.RefreshToken,
        });
    } catch (err) {
        console.error('Erreur lors de l\'authentification :', err.message);
        return res.status(401).json({ error: err.message });
    }
});

app.listen(port, () => {
    console.log(`Serveur en écoute sur http://localhost:${port}`);
});
