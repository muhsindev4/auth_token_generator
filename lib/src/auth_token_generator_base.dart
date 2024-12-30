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
