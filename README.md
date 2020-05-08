Endpoints:

- oauth authorize
    - lookup client ID
    - check redirect_uri (exact match for client IDs)
    - confirm that PKCE and state are provided
    - do G Suite login
    - confirm user group
    - issue code that can be exchanged for auth token/refresh token  
    - redirect to client
- oauth token
    - confirm that client_id, redirect_uri, PKCE, and code are correct
    - confirm user and group are still valid
    - issue access token (expires in 5 minutes)
    - issue refresh token (max lifetime across all renewals 24 hours for web, 1 week for CLI)
- oauth refresh token
    - confirm refresh token is valid and current and matches client_id
    - confirm user and group are still valid
    - issue access token (expires in 5 minutes)
    - revoke previous refresh token
    - issue refresh token (max lifetime capped based on initial refresh grant)
- list refresh tokens
- revoke refresh token

Features:

- users login via OIDC / G Suite
- each cluster is mapped to one or more G Suite domains/groups
- user membership is checked against allowed groups
- disabled/deleted/removed users are no longer allowed at token refresh
- token creation/renewal is logged with user/IP/User-Agent allowing revocation


SET Referrer-Policy: no-referrer
