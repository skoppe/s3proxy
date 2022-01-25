module s3proxy.auth;

import s3proxy.protocol;
import mir.algebraic : Algebraic;
import url;

enum Permission : string {
  read = "read",
  write = "write"
}

struct Access {
  Permission[] permissions;
  Authentication authentication;
}

struct OAuthAuthenticationProvider {
  URL endpoint; // the oauth info endpoint
  string[] scopes;
  WebIdentityAuthentication auth;
}

struct OIDCAuthenticationProvider {
  string issuer;
  string[] scopes;
  WebIdentityAuthentication auth;
}

struct CredentialAuthentication {
  enum type = "credentials";
  string name, key, secret;
  bool matches(string key) @safe pure {
    return this.key == key;
  }
  string getSecret(string key) @safe pure {
    return secret;
  }
  bool isNotExpired(string key) @safe pure {
    return true;
  }
}

alias Authentication = Algebraic!(CredentialAuthentication, WebIdentityAuthentication);

struct WebIdentityAuthentication {
  struct WebIdentityKey {
    enum type = "WEB";
    enum version_ = "A";
    enum prefix = type ~ version_;
    ubyte[6] salt;
    ubyte[4] expiry;
    string toString() const pure @safe {
      import s3proxy.webidentity : keyEncoder;
      import std.range : chain;
      import std.conv : text;
      return text(prefix, chain(salt[], expiry[]).keyEncoder);
    }
  }
  struct Identity {
    string key, secret;
  }
  import core.time : Duration;
  enum type = "web";
  string name, secret;
  ulong expires; // in seconds
  this(string name, string secret, ulong expires = 3600) @safe pure {
    this.name = name;
    this.secret = secret;
    this.expires = expires;
  }
  bool matches(string key) @safe pure {
    return key.length == 20 && key[0..4] == WebIdentityKey.prefix;
  }
  Identity generateIdentity(RNG)(RNG rng) @safe const {
    auto key = generateKey(rng);
    return Identity(key.toString, generateSecret(key));
  }
  static WebIdentityKey parseKey(string raw) @safe pure {
    import s3proxy.webidentity : keyDecoder;
    import std.exception : enforce;
    import std.range : takeExactly, take, refRange;
    import std.string : representation;
    import std.algorithm : copy;
    enforce(raw[0..4] == WebIdentityKey.prefix);
    auto decoder = raw.representation!(immutable(char))[4..$].takeExactly(16).keyDecoder;
    auto bytes = refRange(&decoder);
    WebIdentityKey key;
    (() @trusted => bytes.take(6).copy(key.salt[]))();
    (() @trusted => bytes.take(4).copy(key.expiry[]))();
    return key;
  }
  WebIdentityKey generateKey(RNG)(RNG rng) @safe const {
    import std.random;
    import std.datetime : Clock;
    import std.bitmanip : nativeToLittleEndian;
    import std.range : iota;
    import std.algorithm : map;
    import std.array : staticArray;
    long unixtime = Clock.currTime.roll!"seconds"(expires).toUnixTime!long;
    auto expiry = nativeToLittleEndian(cast(uint)(unixtime & 0xffffffff));
    auto salt = iota(0,6).map!(i => rng.uniform!ubyte);
    return WebIdentityKey(salt.staticArray!6, expiry);
  }
  string generateSecret(WebIdentityKey key) @safe pure const {
    import std.string : representation;
    import std.digest.sha;
    import std.base64;
    import kdf.pbkdf2;
    return Base64.encode(pbkdf2!SHA1(key.toString.representation, secret.representation, 4096, 45));
  }
  bool isNotExpired(string key) @safe {
    import std.datetime : Clock;
    import std.bitmanip : littleEndianToNative;
    long deadline = cast(long)parseKey(key).expiry.littleEndianToNative!uint;
    long unixtime = Clock.currTime.roll!"seconds"(expires).toUnixTime!long;
    return deadline > unixtime;
  }
  string getSecret(string key) @safe pure {
    return generateSecret(parseKey(key));
  }
}

bool authenticateRequest(S3RequestInfo req, Access[] auths) @safe nothrow {
  return authenticateRequest(req, auths);
}

bool authenticateRequest(ref S3RequestInfo req, Access[] auths) @safe nothrow {
  import std.algorithm : filter;
  import std.array : array;
  auto arr = auths.dup();

  arr.runCheck!(matchesAccessKey)(req.signatureHeader.credential.accessKey);
  arr.runCheck!(notExpired)(req.signatureHeader.credential.accessKey);
  arr.runCheck!(hasPermissionFor)(req.guessS3Operation);
  arr.runCheck!(validateSecretKey)(req);

  return arr.length > 0;
}

template runCheck(alias fun) {
  void runCheck(Args...)(ref Access[] arr, auto ref Args args) {
    import std.algorithm : remove;
    import core.lifetime : forward;
    import s3proxy.utils : ifThrown;
    arr = arr.remove!(a => (!fun(a, forward!args)).ifThrown(true));
  }
}

bool matchesAccessKey(Access auth, string accessKey) @safe pure {
  return auth.authentication.matches(accessKey);
}

bool notExpired(Access auth, string accessKey) @safe {
  return auth.authentication.isNotExpired(accessKey);
}

bool hasPermissionFor(Access auth, S3Operation operation) @safe pure {
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

bool validateSecretKey(Access auth, ref S3RequestInfo req) @safe pure {
  import aws.sigv4;
  import std.array : split;
  import std.digest : toHexString;
  import std.string : toLower;
  auto datetime = req.datetime.split("T");
  string region = req.signatureHeader.credential.region;
  string service = req.signatureHeader.credential.service;
  SignableRequest sr = SignableRequest(datetime[0], datetime[1][0..$-1], region, service, req.canonicalRequest);
  string stringToSign = sr.signableString();
  ubyte[32] signKey = signingKey(auth.authentication.getSecret(req.signatureHeader.credential.accessKey), datetime[0], region, service);
  string signature = hmacSha256Sign(signKey, stringToSign);

  return signature == req.signatureHeader.signature;
}
