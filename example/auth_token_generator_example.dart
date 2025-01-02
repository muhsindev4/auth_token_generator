import 'package:auth_token_generator/auth_token_generator.dart';

/// Main function to demonstrate token generation, validation, and custom features.
void main() {
  final String secretKey = 'my_secret_key';

  // Step 1: Generate a bearer token
  final userId = 'user123';
  final token = AuthTokenGenerator.generateBearerToken(secretKey, userId: userId);
  print('Generated Bearer Token: $token');

  // Step 2: Extract user ID from the token
  final extractedUserId = AuthTokenGenerator.getUserIdFromBearerToken(secretKey, token);
  print('Extracted User ID: $extractedUserId');

  // Step 3: Validate the token
  final isValid = AuthTokenGenerator.validateBearerToken(secretKey, token);
  print('Is the Bearer Token valid? $isValid');

  // Step 4: Check if the token is expired
  final isExpired = AuthTokenGenerator.isTokenExpired(token);
  print('Is the Bearer Token expired? $isExpired');

  // Step 5: Decode the token
  final decodedToken = AuthTokenGenerator.decodeBearerToken(token);
  print('Decoded Bearer Token: $decodedToken');

  // Step 6: Generate a refresh token
  final refreshToken = AuthTokenGenerator.generateRefreshToken(secretKey, userId: userId);
  print('Generated Refresh Token: $refreshToken');

  // Step 7: Validate the refresh token
  final isRefreshTokenValid = AuthTokenGenerator.validateRefreshToken(secretKey, refreshToken);
  print('Is the Refresh Token valid? $isRefreshTokenValid');

  // Step 8: Generate a token with custom claims
  final customClaims = {'role': 'admin', 'permissions': ['read', 'write', 'delete']};
  final customToken = AuthTokenGenerator.generateTokenWithCustomClaims(
    secretKey,
    userId: userId,
    customClaims: customClaims,
    expiresIn: 7200,
  );
  print('Generated Token with Custom Claims: $customToken');

  // Step 9: Decode and inspect the custom token
  final decodedCustomToken = AuthTokenGenerator.decodeBearerToken(customToken);
  print('Decoded Custom Token: $decodedCustomToken');
}
