### NGINX Configuration Documentation

This NGINX configuration sets up a reverse proxy for a Node.js application running on `127.0.0.1:8000`. It also handles HTTPS connections and manages client certificates for mutual TLS (mTLS).

#### Upstream Configuration

```nginx
upstream nodeexpressapi {
    # Define the backend server (Node.js app)
    server 127.0.0.1:8000;
    keepalive 64;  # Keep 64 connections alive for reuse
}
```
- **Upstream Block**: Defines a group of servers that NGINX can proxy requests to. Here, it points to a Node.js server running on `127.0.0.1:8000`.

#### HTTPS Server Block

```nginx
server {
    listen 443 ssl; # Enable SSL on port 443
    server_name api.yourserver.com;
```

- **listen 443 ssl**: Configures NGINX to listen on port 443 with SSL/TLS enabled.
- **server_name api.yourserver.com**: Specifies the server's domain name.

##### SSL/TLS Configuration

```nginx
    # Server-side SSL/TLS certificate and key
    ssl_certificate /etc/letsencrypt/live/api.yourserver.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/api.yourserver.com/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
```

- **ssl_certificate**: The path to the SSL certificate provided by Let's Encrypt.
- **ssl_certificate_key**: The path to the SSL private key.
- **include /etc/letsencrypt/options-ssl-nginx.conf**: Includes SSL options configured by Certbot.
- **ssl_dhparam**: Specifies the Diffie-Hellman parameter file for additional security during key exchange.

##### Client-Side SSL/TLS Configuration

```nginx
    # Client-side SSL/TLS certificate settings
    ssl_client_certificate /etc/nginx/client_certs/secureaccess.crt; # Self-signed or trusted CA certs
    ssl_verify_client optional_no_ca; # Request but do not require valid client certs
```

- **ssl_client_certificate**: The path to the file containing trusted CA certificates or client certificates (self-signed) used to verify the client’s certificate.
- **ssl_verify_client optional_no_ca**: Requests a client certificate but does not require it to be signed by a CA in `ssl_client_certificate`. This means the client cert is required but its CA does not have to be trusted. The server will still pass the certificate to the backend for custom validation.

#### Location Block for `/mtls`

This block handles requests to the `/mtls` endpoint, passing them to the backend Node.js application while also passing client certificate information.

```nginx
    location /mtls {
        # Proxy settings
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_set_header X-NginX-Proxy true;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_max_temp_file_size 0;
        proxy_pass http://nodeexpressapi/mtls;
        proxy_redirect off;
        proxy_read_timeout 240s;
```

- **proxy_pass**: Proxies requests to the upstream server (`http://nodeexpressapi/mtls`).
- **proxy_set_header**: Sets various headers to pass information to the backend server:
  - **X-Forwarded-For**: Client’s IP address.
  - **Host**: Original host requested by the client.
  - **X-NginX-Proxy**: Custom header indicating the request is coming through NGINX.
  - **Upgrade**: Enables connection upgrades (e.g., for WebSockets).
  - **Connection**: Manages HTTP connection behavior.
- **proxy_max_temp_file_size**: Controls the maximum size of files NGINX will buffer to disk.
- **proxy_redirect**: Disables automatic redirection handling.
- **proxy_read_timeout**: Sets the timeout for reading from the proxied server.

##### Passing Client Certificate Details

```nginx
        # Pass SSL client certificate details to the backend
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
        proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
        proxy_set_header X-SSL-Client-I-Dn $ssl_client_i_dn;
        proxy_set_header X-SSL-Client-S-Dn $ssl_client_s_dn;
        proxy_set_header X-SSL-Client-Serial $ssl_client_serial;
        proxy_set_header X-SSL-Client-V-Start $ssl_client_v_start;
        proxy_set_header X-SSL-Client-V-End $ssl_client_v_end;
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_set_header X-SSL-Protocol $ssl_protocol;
        proxy_set_header X-SSL-Server-Name $ssl_server_name;
    }
```

- **X-SSL-Client-Cert**: Passes the client certificate in PEM format.
- **X-Client-Cert**: The URL-encoded form of the client certificate.
- **X-SSL-Client-I-Dn**: The distinguished name of the certificate issuer.
- **X-SSL-Client-S-Dn**: The distinguished name of the certificate subject.
- **X-SSL-Client-Serial**: The serial number of the client certificate.
- **X-SSL-Client-V-Start**: The start date of the client certificate validity.
- **X-SSL-Client-V-End**: The end date of the client certificate validity.
- **X-SSL-Client-Verify**: Indicates whether the client certificate was verified.
- **X-SSL-Protocol**: The protocol used for the SSL connection.
- **X-SSL-Server-Name**: The server name requested by the client.

#### Location Block for Root `/`

This block handles all other requests, passing them to the backend Node.js application without requiring mTLS verification.

```nginx
    location / {
        # Default proxy_pass configuration for all other requests
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_set_header X-NginX-Proxy true;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_max_temp_file_size 0;
        proxy_pass http://nodeexpressapi/;
        proxy_redirect off;
        proxy_read_timeout 240s;

        # Pass SSL details to the backend
        proxy_set_header X-SSL-Protocol $ssl_protocol;
        proxy_set_header X-SSL-Server-Name $ssl_server_name;
    }
```

- **proxy_pass**: Proxies requests to the root path of the upstream server.
- **proxy_set_header**: Same as above, setting headers to pass information to the backend.

#### HTTP to HTTPS Redirection

This server block handles redirecting HTTP traffic to HTTPS.

```nginx
server {
    if ($host = api.yourserver.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

    server_name api.yourserver.com;
    listen 80;
    return 404; # managed by Certbot
}
```

- **listen 80**: Listens for HTTP requests on port 80.
- **if ($host = api.yourserver.com)**: Checks if the request is for the specified domain.
- **return 301 https://$host$request_uri**: Redirects to the HTTPS version of the requested URL.
- **return 404**: Returns a 404 error if the request is not for the specified domain.

### Summary

This NGINX configuration handles:
- Reverse proxying to a Node.js Express application.
- SSL/TLS termination for secure HTTPS connections.
- Optional mTLS with client certificates that are not necessarily signed by a trusted CA.
- Passing detailed SSL and client certificate information to the backend.
- Redirecting HTTP traffic to HTTPS for security.

By using this configuration, NGINX can provide secure access and detailed client certificate handling for your API.