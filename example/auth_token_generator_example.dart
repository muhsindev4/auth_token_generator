import 'package:auth_token_generator/auth_token_generator.dart';

/// Main function to demonstrate token generation and user ID extraction.
void main() {
  final String secretKey = 'my_secret_key';

  // Step 1: Generate a bearer token
  final userId = 'user123';
  final token = AuthTokenGenerator.generateBearerToken(secretKey, userId: userId);
  print('Generated Token: $token');

  // Step 2: Extract user ID from the token
  final extractedUserId = AuthTokenGenerator.getUserIdFromBearerToken(secretKey, token);
  print('Extracted User ID: $extractedUserId');

  // Step 3: Validate the token
  final isValid = AuthTokenGenerator.validateBearerToken(secretKey, token);
  print('Is the token valid? $isValid');

  // Step 4: Check if the token is expired
  final isExpired = AuthTokenGenerator.isTokenExpired(token);
  print('Is the token expired? $isExpired');


  final decodeToken = AuthTokenGenerator.decodeBearerToken(token);
  print('Decoded? $decodeToken');
}