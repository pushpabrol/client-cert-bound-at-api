const express = require("express");
const app = express();
const forge = require('node-forge');
const crypto = require('crypto');
const dotenv = require('dotenv');
const { expressjwt: jwt } = require("express-jwt");
const jwks = require('jwks-rsa');
const { JWK, JWE } = require('node-jose');
dotenv.config();

const AUDIENCE = process.env.AUDIENCE;
const JWKS_URI = process.env.JWKS_URI;
const ISSUER = process.env.ISSUER;
const JWE_API_AUDIENCE = process.env.JWE_API_AUDIENCE;
const JWE_PRIVATE_KEY = process.env.JWE_PRIVATE_KEY;

// JWT Check Middleware
var jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: JWKS_URI 
    }),
    audience: AUDIENCE,
    issuer: ISSUER,
    algorithms: ['RS256']
});

var jwtCheckEncryptedAudience = jwt({
  secret: jwks.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: JWKS_URI 
  }),
  audience: JWE_API_AUDIENCE,
  issuer: ISSUER,
  algorithms: ['RS256']
});

// Helper function to calculate the SHA-256 thumbprint of a certificate
const calculateThumbprint = (pemCertificate) => {
    const cert = forge.pki.certificateFromPem(pemCertificate);
    const derCertificate = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    const thumbprint = crypto
        .createHash('sha256')
        .update(Buffer.from(derCertificate.getBytes(),'binary'))
        .digest();

    const base64Thumbprint = Buffer.from(thumbprint).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return base64Thumbprint;
};

// Middleware for verifying access token client certificate binding
const verifyTokenBinding = async (req, res, next) => {
    try {
        const claims = req.auth;
        const cnfClaim = claims.cnf;

        if (!cnfClaim || !cnfClaim['x5t#S256']) {
            return res.status(401).json({ error: 'Token missing x5t#S256 in the cnf claim' });
        }

        const clientCertBase64 = decodeURIComponent(req.get('x-client-cert'));

        if (!clientCertBase64) {
            return res.status(401).json({ error: 'Client certificate not present' });
        }

        const clientCertThumbprint = calculateThumbprint(clientCertBase64);

        if (cnfClaim['x5t#S256'] !== clientCertThumbprint) {
            return res.status(401).json({ error: 'Certificate thumbprint does not match x5t#S256' });
        }

        // Token binding is valid; continue to the next middleware
        next();
    } catch (error) {
        console.error('Error verifying token:', error);
        return res.status(401).json({ error: 'Token verification failed' });
    }
};

// Middleware for decrypting JWE tokens
// Middleware for decrypting JWE tokens
const decryptJWEMiddleware = async (req, res, next) => {
  try {
      const authHeader = req.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'Authorization header missing or malformed' });
      }

      const encryptedToken = authHeader.split(' ')[1];

      // Load the private key for decryption
      const key = await JWK.asKey(process.env.JWE_PRIVATE_KEY.replace(/\n/g,"\r\n"),"pem");
      // Decrypt the JWE token
      const decrypted = await JWE.createDecrypt(key).decrypt(encryptedToken);
      console.log(decrypted);
      const accessToken = decrypted.plaintext.toString('utf-8');
      console.log("Access Token: ", accessToken);

      // Replace the Authorization header with the decrypted JWT
      req.headers['authorization'] = `Bearer ${accessToken}`;

      // Continue to the next middleware
      next();
  } catch (error) {
      console.error('Error decrypting JWE:', error);
      return res.status(401).json({ error: 'Token decryption failed' });
  }
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const HTTP_PORT = 8000;

// Start server
app.listen(HTTP_PORT, () => {
    console.log("Server running on port %PORT%".replace("%PORT%", HTTP_PORT));
});

// Root path
app.get("/", (req, res, next) => {
    res.json({ "message": "Ok", "headers": req.headers });
});

// Protected endpoint with JWT check and token binding verification
app.get("/mtls/protected", jwtCheck, verifyTokenBinding, (req, res, next) => {
    res.json({ "verified token claims": req.auth });
});

// Protected endpoint with JWE decryption, JWT check, and token binding verification
app.get("/mtls/protected/jwe", decryptJWEMiddleware, jwtCheckEncryptedAudience, verifyTokenBinding, (req, res, next) => {
    res.json({ "recieved encrpted jwt token, RS was able to decrypt and verify the token, here are the token claims": req.auth });
});

// Endpoint for general MTLS checks
app.get("/mtls", (req, res, next) => {
    res.json({ "headers": req.headers });
});
