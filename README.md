# Auth Token Generator

Auth Token Generator is a Dart package for generating and validating bearer tokens using HMAC-SHA256 encryption.

## Installation

To use this package, add `auth_token_generator` as a dependency in your `pubspec.yaml` file:


    dependencies:
      auth_token_generator: ^1.1.0

Then, import the package in your Dart code:

`import 'package:auth_token_generator/auth_token_generator.dart';`

## Usage

### Generating Bearer Tokens

You can generate bearer tokens using the `generateBearerToken` method:
`final secretKey = 'my_secret_key';
final userId = 'user123';
final token = AuthTokenGenerator.generateBearerToken(secretKey, userId: userId);
print('Generated token: $token');`


### Extracting User ID from Bearer Tokens

You can extract the user ID from a bearer token using the `getUserIdFromBearerToken` method:

`final extractedUserId = AuthTokenGenerator.getUserIdFromBearerToken(secretKey, token);
if (extractedUserId != null) {
  print('Extracted user ID: $extractedUserId');
} else {
  print('Invalid token or signature.');
}`

### Validating Bearer Tokens

You can validate bearer tokens using the `validateBearerToken` method:

`final isValid = AuthTokenGenerator.validateBearerToken(secretKey, token);
print('Is the token valid? $isValid');`

### Checking Token Expiration

You can check if the token has expired using the `isTokenExpired` method:

`final isExpired = AuthTokenGenerator.isTokenExpired(token);
print('Is the token expired? $isExpired');`

### Decoding Bearer Tokens

You can decode a bearer token without validating the signature using the `decodeBearerToken` method:

`final decoded = AuthTokenGenerator.decodeBearerToken(token);
print('Decoded token: $decoded');`