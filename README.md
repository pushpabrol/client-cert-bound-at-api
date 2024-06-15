
# Node.js API with JWT, JWE, and MTLS

## Overview

This API demonstrates secure token handling using JWT (JSON Web Token), JWE (JSON Web Encryption), and MTLS (Mutual TLS) for client certificate binding. It is designed to work with Auth0 for authentication and authorization. The API includes endpoints that validate tokens, decrypt JWE tokens, and ensure secure communication with client certificates.

## Features

- **JWT Validation**: Validates JWT tokens using `express-jwt` and Auth0's JWKS (JSON Web Key Set) endpoint.
- **JWE Decryption**: Decrypts encrypted JWE tokens and extracts the JWT for further validation.
- **MTLS (Mutual TLS)**: Verifies client certificates and binds tokens to client certificates.
- **Secure Endpoints**: Provides secure endpoints that require valid and decrypted tokens for access.

## Prerequisites

- **Node.js**: Ensure you have Node.js installed.
- **Auth0**: Set up an Auth0 tenant and configure your API.
- **Environment Variables**: Create a `.env` file in the project root with the following keys:
- **A proxy for HTTPS and MUTUAL TLS**: See [Proxy Setup document](nginx_setup/README.md) for details on how to host this API behind a proxy

  ```env
  AUDIENCE=<Your Auth0 API Audience>
  JWKS_URI=https://<your-auth0-domain>/.well-known/jwks.json
  ISSUER=https://<your-auth0-domain>/
  JWE_API_AUDIENCE=<Audience for JWE encrypted tokens>
  JWE_PRIVATE_KEY=<Your Private Key for JWE decryption>
  ```

## Installation

1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Set Up Environment Variables**:
   - Rename `.env.example` to `.env` and update it with your Auth0 details and JWE private key.

4. **Start the Server**:
   ```bash
   npm start
   ```
   The server will start on port 8000.

## API Endpoints

### Root Endpoint

- **URL**: `/`
- **Method**: `GET`
- **Description**: Returns a welcome message and the request headers.
- **Response**:
  ```json
  {
    "message": "Ok",
    "headers": { ... }
  }
  ```

### MTLS Protected Endpoint

- **URL**: `/mtls/protected`
- **Method**: `GET`
- **Description**: Validates JWT tokens and verifies client certificate binding.
- **Middlewares**: `jwtCheck`, `verifyTokenBinding`
- **Response**: JSON object with verified token claims.
- **Sample Response**:
  ```json
  {
    "verified token claims": { ... }
  }
  ```

### JWE Decrypted and MTLS Protected Endpoint

- **URL**: `/mtls/protected/jwe`
- **Method**: `GET`
- **Description**: Decrypts JWE tokens, validates the decrypted JWT, and verifies client certificate binding.
- **Middlewares**: `decryptJWEMiddleware`, `jwtCheckEncryptedAudience`, `verifyTokenBinding`
- **Response**: JSON object with decrypted and verified token claims.
- **Sample Response**:
  ```json
  {
    "recieved encrpted jwt token, RS was able to decrypt and verify the token, here are the token claims": { ... }
  }
  ```

### General MTLS Check Endpoint

- **URL**: `/mtls`
- **Method**: `GET`
- **Description**: Returns request headers for general MTLS check.
- **Response**:
  ```json
  {
    "headers": { ... }
  }
  ```

## Middleware Explanation

### JWT Check (`jwtCheck` and `jwtCheckEncryptedAudience`)

- **Purpose**: Validates JWT tokens against the configured Auth0 audience and issuer using the JWKS endpoint.
- **Configuration**:
  - Uses `express-jwt` to check the token in the `Authorization` header.
  - Verifies the token signature with keys obtained from the JWKS URI.

### Decrypt JWE Middleware (`decryptJWEMiddleware`)

- **Purpose**: Decrypts JWE tokens to reveal the encapsulated JWT.
- **Process**:
  - Extracts the JWE token from the `Authorization` header.
  - Uses the configured private key to decrypt the token.
  - Replaces the `Authorization` header with the decrypted JWT for subsequent validation.

### Verify Token Binding (`verifyTokenBinding`)

- **Purpose**: Ensures that the token is bound to the client certificate.
- **Process**:
  - Calculates the SHA-256 thumbprint of the client's certificate.
  - Compares the thumbprint with the `x5t#S256` claim in the token.
  - Validates that the token is used by the legitimate client.

## Environment Configuration

- **.env File**: Store your sensitive configuration details here. The application reads the following variables:
  - `AUDIENCE`: The expected audience for JWT validation.
  - `JWKS_URI`: The URI for fetching the JSON Web Key Set from Auth0.
  - `ISSUER`: The expected issuer for JWT validation.
  - `JWE_API_AUDIENCE`: The expected audience for the JWE encrypted tokens.
  - `JWE_PRIVATE_KEY`: The private key used to decrypt JWE tokens. Format the key correctly in the environment file to avoid issues.

## Example `env` File

```env
AUDIENCE=https://api.example.com
JWKS_URI=https://example.auth0.com/.well-known/jwks.json
ISSUER=https://example.auth0.com/
JWE_API_AUDIENCE=https://api.example.com/jwe
JWE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASCATwwggE4AgEAAkEAqjI2...\n-----END PRIVATE KEY-----"
```

## Security Considerations

- **MTLS**: Ensures secure client-server communication by requiring client certificates.
- **Token Binding**: Prevents token misuse by binding tokens to the client's certificate.
- **JWT and JWE**: Provides secure and encrypted token handling for enhanced security.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
