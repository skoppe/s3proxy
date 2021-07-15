module s3proxy.auth;

import s3proxy.protocol;
import s3proxy.config;

bool authenticateRequest(S3RequestInfo req, Authentication[] auths) @safe pure nothrow {
  return authenticateRequest(req, auths);
}

bool authenticateRequest(ref S3RequestInfo req, Authentication[] auths) @safe pure nothrow {
  import std.algorithm : filter;
  import std.array : array;
  auto arr = auths.dup();

  arr.runCheck!(matchesAccessKey)(req.signatureHeader.credential.accessKey);
  arr.runCheck!(hasPermissionFor)(req.guessS3Operation);
  arr.runCheck!(validateSecretKey)(req);

  return arr.length > 0;
}

template runCheck(alias fun) {
  void runCheck(Args...)(ref Authentication[] arr, auto ref Args args) {
    import std.algorithm : remove;
    import core.lifetime : forward;
    import s3proxy.utils : ifThrown;
    arr = arr.remove!(a => (!fun(a, forward!args)).ifThrown(true));
  }
}

bool matchesAccessKey(Authentication auth, string accessKey) @safe pure {
  return auth.authenticator.matches(accessKey);
}

bool hasPermissionFor(Authentication auth, S3Operation operation) @safe pure {
  import std.algorithm : canFind;
  final switch (operation) with(S3Operation) {
    case info:
    case list:
    case download:
      return auth.permissions.canFind(Permission.read);
    case upload:
    case uploadMultipartStart:
    case uploadMultipartFinish:
    case uploadMultipart:
      return auth.permissions.canFind(Permission.write);
    case unknown: return false;
    }
}

bool validateSecretKey(Authentication auth, ref S3RequestInfo req) @safe pure {
  import aws.sigv4;
  import std.array : split;
  import std.digest : toHexString;
  import std.string : toLower;
  auto datetime = req.datetime.split("T");
  string region = req.signatureHeader.credential.region;
  string service = req.signatureHeader.credential.service;
  SignableRequest sr = SignableRequest(datetime[0], datetime[1][0..$-1], region, service, req.canonicalRequest);
  string stringToSign = sr.signableString();
  ubyte[32] signKey = signingKey(auth.authenticator.secret, datetime[0], region, service);
  string signature = hmacSha256Sign(signKey, stringToSign);

  return signature == req.signatureHeader.signature;
}
