import 'dart:convert';
import 'package:crypto/crypto.dart'; // Importing crypto library for cryptographic operations

/// A class for generating and validating bearer tokens.
class AuthTokenGenerator {

  /// Generates a bearer token with the provided [secretKey], [userId], and optional [expiresIn] duration.
  /// Returns the generated bearer token string.
  static String generateBearerToken(String secretKey, {String? userId, int expiresIn = 3600}) {
    // Creating claims for the token
    final claims = {
      'exp': DateTime.now().add(Duration(seconds: expiresIn)).millisecondsSinceEpoch ~/ 1000,
      'userId': userId,
    };

    // Encoding header and payload in JSON format
    final header = '{"alg":"HS256","typ":"JWT"}';
    final payload = jsonEncode(claims);

    // Encoding header and payload in base64
    final headerBase64 = base64Url.encode(utf8.encode(header));
    final payloadBase64 = base64Url.encode(utf8.encode(payload));
    // Generating signature using HMAC-SHA256 algorithm
    final signatureBase64 = base64Url.encode(Hmac(sha256, utf8.encode(secretKey))
        .convert('$headerBase64.$payloadBase64'.codeUnits)
        .bytes);

    // Returning the generated token
    return '$headerBase64.$payloadBase64.$signatureBase64';
  }

  /// Generates a refresh token with the provided [secretKey], [userId], and optional [expiresIn] duration.
  ///
  /// The refresh token is a special type of token used to obtain a new bearer token
  /// without requiring the user to reauthenticate. The default expiration time is one week (604800 seconds).
  ///
  /// - [secretKey]: The secret key used to sign the token.
  /// - [userId]: The unique identifier for the user.
  /// - [expiresIn]: The token's expiration time in seconds (default is 7 days).
  ///
  /// Returns the generated refresh token string.
  static String generateRefreshToken(String secretKey, {required String userId, int expiresIn = 604800}) {
    final claims = {
      'exp': DateTime.now().add(Duration(seconds: expiresIn)).millisecondsSinceEpoch ~/ 1000,
      'userId': userId,
      'type': 'refresh',
    };

    final header = '{"alg":"HS256","typ":"JWT"}';
    final payload = jsonEncode(claims);
    final headerBase64 = base64Url.encode(utf8.encode(header));
    final payloadBase64 = base64Url.encode(utf8.encode(payload));
    final signatureBase64 = base64Url.encode(Hmac(sha256, utf8.encode(secretKey))
        .convert('$headerBase64.$payloadBase64'.codeUnits)
        .bytes);

    return '$headerBase64.$payloadBase64.$signatureBase64';
  }

  /// Validates the provided refresh [token] using the specified [secretKey].
  ///
  /// A valid refresh token must:
  /// - Have the correct type (`"refresh"`) in its claims.
  /// - Pass the signature validation and expiration checks.
  ///
  /// - [secretKey]: The secret key used to validate the token's signature.
  /// - [token]: The refresh token to validate.
  ///
  /// Returns `true` if the refresh token is valid, otherwise `false`.
  static bool validateRefreshToken(String secretKey, String token) {
    final claims = decodeBearerToken(token);
    if (claims == null || claims['type'] != 'refresh') {
      return false; // Not a valid refresh token
    }
    return validateBearerToken(secretKey, token);
  }

  /// Generates a token with custom claims and an expiration time.
  ///
  /// This method allows for the inclusion of custom claims in addition to standard claims like `exp` and `userId`.
  /// It generates a JWT (JSON Web Token) signed using the HMAC-SHA256 algorithm.
  ///
  /// - [secretKey]: The secret key used to sign the token.
  /// - [userId]: The unique identifier for the user.
  /// - [customClaims]: A map of additional claims to include in the token. Default is an empty map.
  /// - [expiresIn]: The token's expiration time in seconds. Default is 3600 seconds (1 hour).
  ///
  /// Returns the generated token string.
  ///
  /// Example usage:
  /// ```dart
  /// final token = AuthTokenGenerator.generateTokenWithCustomClaims(
  ///   'mySecretKey',
  ///   userId: '12345',
  ///   customClaims: {'role': 'admin', 'permissions': ['read', 'write']},
  ///   expiresIn: 7200,
  /// );
  /// ```
  static String generateTokenWithCustomClaims(
      String secretKey, {
        required String userId,
        Map<String, dynamic> customClaims = const {},
        int expiresIn = 3600,
      }) {
    final claims = {
      'exp': DateTime.now().add(Duration(seconds: expiresIn)).millisecondsSinceEpoch ~/ 1000,
      'userId': userId,
      ...customClaims,
    };

    final header = '{"alg":"HS256","typ":"JWT"}';
    final payload = jsonEncode(claims);
    final headerBase64 = base64Url.encode(utf8.encode(header));
    final payloadBase64 = base64Url.encode(utf8.encode(payload));
    final signatureBase64 = base64Url.encode(Hmac(sha256, utf8.encode(secretKey))
        .convert('$headerBase64.$payloadBase64'.codeUnits)
        .bytes);

    return '$headerBase64.$payloadBase64.$signatureBase64';
  }

  /// Extracts the user ID from the provided bearer [token] using the specified [secretKey].
  /// Returns the extracted user ID if successful, otherwise returns null.
  static String? getUserIdFromBearerToken(String secretKey, String token) {
    // Splitting the token into parts (header, payload, signature)
    final parts = token.split('.');
    // Checking if the token has valid format
    if (parts.length != 3) {
      // Invalid token format
      return null;
    }

    // Decoding payload from base64
    final payload = parts[1];
    final decodedPayload = utf8.decode(base64Url.decode(payload));
    // Parsing JSON payload into a map
    final Map<String, dynamic> claims = jsonDecode(decodedPayload);

    // Returning the user ID from the claims
    return claims['userId'];
  }


  /// Validates the provided bearer [token] using the specified [secretKey].
  /// Returns `true` if the token is valid and not expired, otherwise `false`.
  static bool validateBearerToken(String secretKey, String token) {
    final parts = token.split('.');
    if (parts.length != 3) {
      return false; // Invalid token format
    }

    // Decoding the payload
    final payload = parts[1];
    final decodedPayload = utf8.decode(base64Url.decode(payload));
    final Map<String, dynamic> claims = jsonDecode(decodedPayload);

    // Checking if the token has expired
    final exp = claims['exp'];
    if (exp == null || DateTime.now().millisecondsSinceEpoch ~/ 1000 > exp) {
      return false; // Token is expired
    }

    // Verifying the signature (similar to how the token was generated)
    final headerBase64 = parts[0];
    final payloadBase64 = parts[1];
    final signatureBase64 = parts[2];

    final signature = base64Url.encode(Hmac(sha256, utf8.encode(secretKey))
        .convert('$headerBase64.$payloadBase64'.codeUnits)
        .bytes);

    return signatureBase64 == signature; // Check if the signature matches
  }


  /// Decodes the bearer [token] without validating the signature.
  /// Returns the claims as a map.
  static Map<String, dynamic>? decodeBearerToken(String token) {
    final parts = token.split('.');
    if (parts.length != 3) {
      return null; // Invalid token format
    }

    final payload = parts[1];
    final decodedPayload = utf8.decode(base64Url.decode(payload));
    return jsonDecode(decodedPayload); // Returning decoded claims
  }


  /// Checks if the token has expired based on its [exp] claim.
  /// Returns `true` if expired, `false` if still valid.
  static bool isTokenExpired(String token) {
    final claims = decodeBearerToken(token);
    if (claims == null || claims['exp'] == null) {
      return true; // Invalid token or no exp claim
    }

    final expirationTime = DateTime.fromMillisecondsSinceEpoch(claims['exp'] * 1000);
    return DateTime.now().isAfter(expirationTime);
  }

}
