
## [1.2.0] - 2025-01-02
- Added `generateRefreshToken` method for creating refresh tokens with a configurable expiration time.
- Added `validateRefreshToken` method to validate refresh tokens specifically.
- Added `generateTokenWithCustomClaims` method for generating tokens with custom claims.
- Updated the README with examples for the newly added methods.
- Improved documentation and inline comments for clarity.

## [1.1.0] - 2024-12-30
- Added `decodeBearerToken` method for decoding tokens without validating the signature.
- Added `isTokenExpired` method to check if a token is expired based on its `exp` claim.
- Updated the README with usage examples for all methods in the `AuthTokenGenerator` class.

## [1.0.0] - 2024-06-16
- Initial version of `auth_token_generator`.
- Implemented methods for generating and validating bearer tokens using HMAC-SHA256 encryption.
- Included methods for extracting user IDs and verifying token expiration.
