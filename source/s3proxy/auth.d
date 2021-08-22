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

auto dequeue(Range, T)(ref Range range, lazy T def) {
  import std.range : empty, front, popFront;
  if (range.empty)
    return def;
  auto r = range.front;
  range.popFront;
  return r;
}

static immutable char[32] keyChars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7'];

ubyte keyCharToByte(char k) @safe pure nothrow @nogc {
  if ((k - 'A') >= 0 && (k - 'A') < 26)
    return cast(ubyte)(k - 'A');
  return cast(ubyte)(k - '2' + 26);
}

struct KeyEncoder(Range) {
  private Range range;
  ubyte[8] buffer;
  size_t pos;
  this(Range range) {
    this.range = range;
    encodeIntoBuffer();
  }
  private void encodeIntoBuffer() {
    ubyte def = 0;
    ubyte a = range.dequeue(def);
    ubyte b = range.dequeue(def);
    ubyte c = range.dequeue(def);
    ubyte d = range.dequeue(def);
    ubyte e = range.dequeue(def);
    buffer[0] = a >> 3; // 5 from a
    buffer[1] = (a << 2) & 0x1F | (b >> 6); // 3 from a and 2 from b
    buffer[2] = (b >> 1) & 0x1F; // 5 from b
    buffer[3] = (b << 4) & 0x1F | (c >> 4); // 1 from b and 4 from c
    buffer[4] = (c << 1) & 0x1F | (d >> 7); // 4 from c and 1 from d
    buffer[5] = (d >> 2) & 0x1F; // 5 from d
    buffer[6] = (d << 3) & 0x1F | (e >> 5); // 2 from d and 3 from e
    buffer[7] = e & 0x1F; // 5 from e
    pos = 0;
  }
  bool empty() {
    return pos == 8;
  }
  void popFront() {
    import std.range : empty;
    if (pos == 7 && !range.empty)
      encodeIntoBuffer();
    else
      pos++;
  }
  char front() {
    return keyChars[buffer[pos]];
  }
}

auto keyEncoder(Range)(Range r) {
  return KeyEncoder!Range(r);
}

struct KeyDecoder(Range) {
  private Range range;
  ubyte[8] buffer;
  size_t pos;
  this(Range range) @safe {
    this.range = range;
    encodeIntoBuffer();
  }
  private void encodeIntoBuffer() @safe {
    ubyte def = 0;
    buffer[0] = range.dequeue(def).keyCharToByte;
    buffer[1] = range.dequeue(def).keyCharToByte;
    buffer[2] = range.dequeue(def).keyCharToByte;
    buffer[3] = range.dequeue(def).keyCharToByte;
    buffer[4] = range.dequeue(def).keyCharToByte;
    buffer[5] = range.dequeue(def).keyCharToByte;
    buffer[6] = range.dequeue(def).keyCharToByte;
    buffer[7] = range.dequeue(def).keyCharToByte;
    buffer[0] = ((buffer[0] << 3) & 0xff) | (buffer[1] >> 2);
    buffer[1] = ((buffer[1] << 6) & 0xff) | ((buffer[2] << 1) & 0xff) | (buffer[3] >> 4);
    buffer[2] = ((buffer[3] << 4) & 0xff) | (buffer[4] >> 1);
    buffer[3] = ((buffer[4] << 7) & 0xff) | ((buffer[5] << 2) & 0xff) | (buffer[6] >> 3);
    buffer[4] = ((buffer[6] << 5) & 0xff) | buffer[7];
    pos = 0;
  }
  bool empty() @safe const {
    return pos == 5;
  }
  void popFront() @safe {
    import std.range : empty;
    if (pos == 4 && !range.empty)
      encodeIntoBuffer();
    else
      pos++;
  }
  ubyte front() @safe const {
    return buffer[pos];
  }
}

auto keyDecoder(Range)(Range r) {
  return KeyDecoder!Range(r);
}

struct WebIdentityAuthentication {
  struct WebIdentityKey {
    enum type = "WEB";
    enum version_ = "A";
    enum prefix = type ~ version_;
    ubyte[6] salt;
    ubyte[4] expiry;
    string toString() const pure @safe {
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
    import std.exception : enforce;
    import std.range : takeExactly, take, refRange;
    import std.string : representation;
    import std.algorithm : copy;
    enforce(raw[0..4] == WebIdentityKey.prefix);
    auto decoder = raw.representation!(immutable(char))[4..$].takeExactly(16).keyDecoder;
    auto bytes = refRange(&decoder);
    WebIdentityKey key;
    bytes.take(6).copy(key.salt[]);
    bytes.take(4).copy(key.expiry[]);
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
