
## [1.1.0] - 2024-12-30
- Added `decodeBearerToken` method for decoding tokens without validating the signature.
- Added `isTokenExpired` method to check if a token is expired based on its `exp` claim.
- Updated the README with usage examples for all methods in the `AuthTokenGenerator` class.

## [1.0.0] - 2024-06-16
- Initial version of `auth_token_generator`.
- Implemented methods for generating and validating bearer tokens using HMAC-SHA256 encryption.
- Included methods for extracting user IDs and verifying token expiration.

