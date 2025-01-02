# Auth Token Generator

Auth Token Generator is a Dart package for generating, validating, and managing bearer tokens using HMAC-SHA256 encryption.

## Installation

To use this package, add `auth_token_generator` as a dependency in your `pubspec.yaml` file:

```yaml
dependencies:
  auth_token_generator: ^1.1.0
```

Then, import the package in your Dart code:

```dart
import 'package:auth_token_generator/auth_token_generator.dart';
```

## Usage

### Generating Bearer Tokens

Generate bearer tokens using the `generateBearerToken` method:

```dart
final secretKey = 'my_secret_key';
final userId = 'user123';
final token = AuthTokenGenerator.generateBearerToken(secretKey, userId: userId);
print('Generated token: \$token');
```

---

### Extracting User ID from Bearer Tokens

Extract the user ID from a bearer token using the `getUserIdFromBearerToken` method:

```dart
final extractedUserId = AuthTokenGenerator.getUserIdFromBearerToken(secretKey, token);
if (extractedUserId != null) {
  print('Extracted user ID: \$extractedUserId');
} else {
  print('Invalid token or signature.');
}
```

---

### Validating Bearer Tokens

Validate bearer tokens using the `validateBearerToken` method:

```dart
final isValid = AuthTokenGenerator.validateBearerToken(secretKey, token);
print('Is the token valid? \$isValid');
```

---

### Checking Token Expiration

Check if the token has expired using the `isTokenExpired` method:

```dart
final isExpired = AuthTokenGenerator.isTokenExpired(token);
print('Is the token expired? \$isExpired');
```

---

### Decoding Bearer Tokens

Decode a bearer token without validating the signature using the `decodeBearerToken` method:

```dart
final decoded = AuthTokenGenerator.decodeBearerToken(token);
print('Decoded token: \$decoded');
```

---

### Generating Refresh Tokens

Generate refresh tokens using the `generateRefreshToken` method:

```dart
final refreshToken = AuthTokenGenerator.generateRefreshToken(secretKey, userId: userId);
print('Generated refresh token: \$refreshToken');
```

Refresh tokens typically have a longer expiration period and are used to issue new bearer tokens.

---

### Validating Refresh Tokens

Validate refresh tokens using the `validateRefreshToken` method:

```dart
final isRefreshTokenValid = AuthTokenGenerator.validateRefreshToken(secretKey, refreshToken);
print('Is the refresh token valid? \$isRefreshTokenValid');
```

This method ensures that the token is of type `refresh` and checks its validity.

---

### Generating Tokens with Custom Claims

Generate tokens with additional custom claims using the `generateTokenWithCustomClaims` method:

```dart
final customClaims = {'role': 'admin', 'permissions': ['read', 'write', 'delete']};
final customToken = AuthTokenGenerator.generateTokenWithCustomClaims(
  secretKey,
  userId: userId,
  customClaims: customClaims,
  expiresIn: 7200,
);
print('Generated token with custom claims: \$customToken');
```

This allows you to add specific claims relevant to your application's business logic.

---

### Decoding Tokens with Custom Claims

Decode a token with custom claims to view its data:

```dart
final decodedCustomToken = AuthTokenGenerator.decodeBearerToken(customToken);
print('Decoded custom token: \$decodedCustomToken');
```

The decoded token will include custom claims alongside standard claims like `userId` and `exp`.

---

### Example Workflow

```dart
void main() {
  final secretKey = 'my_secret_key';
  final userId = 'user123';

  // Generate a bearer token
  final token = AuthTokenGenerator.generateBearerToken(secretKey, userId: userId);
  print('Bearer Token: \$token');

  // Validate the token
  final isValid = AuthTokenGenerator.validateBearerToken(secretKey, token);
  print('Is Token Valid? \$isValid');

  // Generate a refresh token
  final refreshToken = AuthTokenGenerator.generateRefreshToken(secretKey, userId: userId);
  print('Refresh Token: \$refreshToken');

  // Validate the refresh token
  final isRefreshTokenValid = AuthTokenGenerator.validateRefreshToken(secretKey, refreshToken);
  print('Is Refresh Token Valid? \$isRefreshTokenValid');

  // Decode the bearer token
  final decodedToken = AuthTokenGenerator.decodeBearerToken(token);
  print('Decoded Token: \$decodedToken');
}
