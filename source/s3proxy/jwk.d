module s3proxy.jwk;

import s3proxy.jwt;
import s3proxy.crypto;

struct JWK {
  string alg;
  string kid;
  string key;
}

struct JWKS {
  JWK[] keys;
}

struct JWKSCache {
  import core.sync.mutex : Mutex;
  JWKS[string] jwks;
  private __gshared Mutex mutex;
  JWKS get(string issuer) @safe {
    return jwks.require(issuer, fetchValidationKeys(issuer));
  }
  JWKS get(string issuer) @safe shared {
    with(threadSafe) {
      return obj.jwks.require(issuer, fetchValidationKeys(issuer));
    }
  }
  private ref auto threadSafe() shared @trusted scope return {
    struct Guard {
      JWKSCache* obj;
      Mutex mutex;
      @disable this(ref return scope inout typeof(this) rhs);
      @disable this(this);
      this(shared(JWKSCache)* obj, Mutex m) @trusted {
        this.obj = cast(JWKSCache*)obj;
        mutex = m;
        mutex.lock_nothrow();
      }
      ~this() @safe {
        mutex.unlock_nothrow();
      }
      alias obj this;
    }
    return Guard(&this, getMutex);
  }
  Mutex getMutex() @trusted shared {
    import std.concurrency : initOnce;
    return initOnce!mutex(new Mutex);
  }
}

JWKS fetchValidationKeys(string issuer) @trusted {
  import url;
  import std.json;
  import requests;
  auto location = (issuer.parseURL ~ ".well-known/openid-configuration").toString;
  auto config = parseJSON(cast(string)getContent(location).data);
  auto keysLocation = config["jwks_uri"].str;
  auto jwks = cast(string)getContent(keysLocation).data;
  return jwks.parseJwksKeys();
}

JWKS parseJwksKeys(string raw) @trusted {
  import std.json;
  import std.algorithm : map;
  import std.array : array;
  import std.exception : enforce;
  auto config = parseJSON(raw);
  return JWKS(config["keys"].array.map!((key){
        string kid = key["kid"].str;
        string kty = key["kty"].str;
        string alg = key["alg"].str;
        if (kty == "RSA") {
          string e = key["e"].str;
          string n = key["n"].str;
          string k = extractPublicKeyFromModulusAndExponent(n, e);
          return JWK(alg, kid, k);
        }
        if (kty == "EC") {
          string crv = key["crv"].str;
          string x = key["x"].str;
          string y = key["y"].str;
          string k = extractPublicKeyFromXYCoords(crv, x, y);
          return JWK(alg, kid, k);
        }
        throw new Exception("Unsupported key type "~kty);
      }).array());
}

JWT validateRawJwtSignature(RawJWT jwt, JWKS jwks) @trusted {
  import std.exception : enforce;
  import std.algorithm : find;
  import std.range : empty, front;

  string alg = jwt.header["alg"].str;
  string kid = jwt.header["kid"].str;
  enforce(alg != "none", "none algorithm not supported");
  auto key = jwks.keys.find!(k => k.kid == kid && k.alg == alg);
  if (key.empty)
    throw new Exception("cannot find kid=["~kid~"] in jwks where alg=["~alg~"]");
  auto jwk = key.front();
  return s3proxy.jwt.validateRawJwtSignature(jwt, jwk.key);
}
