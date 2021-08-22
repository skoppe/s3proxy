module s3proxy.jwt;

import std.json;
import std.base64;
import std.range;
import std.algorithm;
import std.format : format;

struct JWT {
  JSONValue json;
}

struct RawJWT {
  import jwtd.jwt : JWTAlgorithm;
  string[] parts;
  JSONValue header;
  JSONValue payload;
  JWTAlgorithm alg;
}

RawJWT decodeRawJwt(string token) @trusted {
  import jwtd.jwt;
	import std.algorithm : count;
	import std.conv : to;
	import std.uni : toUpper;

	if(count(token, ".") != 2)
		throw new VerifyException("Token is incorrect.");

	string[] tokenParts = split(token, ".");

	JSONValue header;
	try {
		header = parseJSON(urlsafeB64Decode(tokenParts[0]));
	} catch(Exception e) {
		throw new VerifyException("Header is incorrect.");
	}

	JWTAlgorithm alg;
	try {
		// toUpper for none
		alg = to!(JWTAlgorithm)(toUpper(header["alg"].str()));
	} catch(Exception e) {
		throw new VerifyException("Algorithm is incorrect.");
	}

  if (alg == JWTAlgorithm.NONE) {
		throw new VerifyException("Algorithm none is not supported.");
  }

	if (auto typ = "typ" in header) {
		string typ_str = typ.str();
		if(typ_str && typ_str != "JWT")
			throw new VerifyException("Type is incorrect.");
	}

	JSONValue payload;

	try {
		payload = parseJSON(urlsafeB64Decode(tokenParts[1]));
	} catch(JSONException e) {
		throw new VerifyException("Payload JSON is incorrect.");
	}

  return RawJWT(tokenParts, header, payload, alg);
}

JWT validateRawJwtSignature(RawJWT jwt, JWKS jwks) @trusted {
  import jwtd.jwt;
  import std.exception : enforce;
  string alg = jwt.header["alg"].str;
  string kid = jwt.header["kid"].str;
  enforce(alg != "none", "none algorithm not supported");
  auto key = jwks.keys.find!(k => k.kid == kid && k.alg == alg);
  if (key.empty)
    throw new Exception("cannot find kid=["~kid~"] in jwks where alg=["~alg~"]");
  auto jwk = key.front();
  return validateRawJwtSignature(jwt, jwk.key);
}

JWT validateRawJwtSignature(RawJWT jwt, string key) @trusted {
  import jwtd.jwt;
  auto signature = Base64URLNoPadding.decode(jwt.parts[2]);
	if(!verifySignature(signature, jwt.parts[0]~"."~jwt.parts[1], key, jwt.alg))
		throw new VerifyException("Signature is incorrect.");

  return JWT(jwt.payload);
}

import jwtd.jwt : JWTAlgorithm;

bool verifySignature(ubyte[] signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
  import std.experimental.logger;
  import jwtd.jwt;
	import deimos.openssl.ssl;
	import deimos.openssl.pem;
	import deimos.openssl.rsa;
	import deimos.openssl.hmac;
	import deimos.openssl.err;
		bool verify_rs(ubyte* hash, int type, uint signLen) {
			RSA* rsa_public = RSA_new();
			scope(exit) RSA_free(rsa_public);

			BIO* bpo = BIO_new_mem_buf(cast(char*)key.ptr, -1);
			if(bpo is null)
				throw new Exception("Can't load key to the BIO.");
			scope(exit) BIO_free(bpo);

			RSA* rsa = PEM_read_bio_RSA_PUBKEY(bpo, &rsa_public, null, null);
			if(rsa is null) {
				throw new Exception("Can't create RSA key.");
			}

			int ret = RSA_verify(type, hash, signLen, signature.ptr, cast(uint)signature.length, rsa_public);
			return ret == 1;
		}

		bool verify_es(uint curve_type, ubyte* hash, int hashLen ) {
			EC_KEY* eckey = getESPublicKey(curve_type, key);
			scope(exit) EC_KEY_free(eckey);

			ubyte* c = cast(ubyte*)signature.ptr;
			ECDSA_SIG* sig = null;
			sig = d2i_ECDSA_SIG(&sig, cast(const (ubyte)**)&c, cast(int) key.length);
			if (sig is null) {
				throw new Exception("Can't decode ECDSA signature.");
			}
			scope(exit) ECDSA_SIG_free(sig);

			int ret =  ECDSA_do_verify(hash, hashLen, sig, eckey);
			return ret == 1;
		}

		switch(algo) {
			case JWTAlgorithm.NONE: {
				return key.length == 0;
			}
			case JWTAlgorithm.HS256:
			case JWTAlgorithm.HS384:
			case JWTAlgorithm.HS512: {
				return signature == sign(signing_input, key, algo);
			}
			case JWTAlgorithm.RS256: {
				ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
				SHA256(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_rs(hash.ptr, NID_sha256, SHA256_DIGEST_LENGTH);
			}
			case JWTAlgorithm.RS384: {
				ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
				SHA384(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_rs(hash.ptr, NID_sha384, SHA384_DIGEST_LENGTH);
			}
			case JWTAlgorithm.RS512: {
				ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
				SHA512(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_rs(hash.ptr, NID_sha512, SHA512_DIGEST_LENGTH);
			}

			case JWTAlgorithm.ES256:{
				ubyte[] hash = new ubyte[SHA256_DIGEST_LENGTH];
				SHA256(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_es(NID_secp256k1, hash.ptr, SHA256_DIGEST_LENGTH );
			}
			case JWTAlgorithm.ES384:{
				ubyte[] hash = new ubyte[SHA384_DIGEST_LENGTH];
				SHA384(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_es(NID_secp384r1, hash.ptr, SHA384_DIGEST_LENGTH );
			}
			case JWTAlgorithm.ES512: {
				ubyte[] hash = new ubyte[SHA512_DIGEST_LENGTH];
				SHA512(cast(const(ubyte)*)signing_input.ptr, signing_input.length, hash.ptr);
				return verify_es(NID_secp521r1, hash.ptr, SHA512_DIGEST_LENGTH );
			}

			default:
				throw new VerifyException("Wrong algorithm.");
		}
	}

bool checkScopes(JWT jwt, const string[] scopes) @safe {
  import std.string : split;
  import std.algorithm : canFind, all;
  auto js = jwt.json["scope"];
  if (js.type == JSON_TYPE.STRING) {
    string[] jwtScopes = js.str.split(" ");
    return scopes.all!(s => jwtScopes.canFind(s));
  }
  return false;
}

// __gshared Json auth0Keys = Json.undefined;

// auto fetchAuth0PublicKeys(string url) {
//   if (auth0Keys.type == Json.Type.Undefined)
//     auth0Keys = requestHTTP(url).readJson()["keys"];
//   return auth0Keys;
// }

// __gshared string[string] auth0PublicKeys;

// auto getAuth0PublicKey(string kid) {
//   if (auto p = kid in auth0PublicKeys)
//     return *p;
//   if (auth0Keys.type == Json.Type.Undefined)
//     throw new Exception("public keys have not been loaded");
//   auto item = auth0Keys.byValue().find!(j => j["kid"].get!string == kid);
//   if (item.empty)
//     throw new Exception("Failed to retrieve key for %s".format(kid));
//   auto key = item.front["x5c"][0].get!string.extractPublicKeyFromCert;
//   auth0PublicKeys[kid] = key;
//   return key;
// }

string extractPublicKeyFromCert(string cert) @trusted {
  import deimos.openssl.ssl;
  import deimos.openssl.pem;
  import deimos.openssl.rsa;
  import deimos.openssl.hmac;
  import deimos.openssl.err;
  auto raw = Base64.decode(cert);
  auto ptr = raw.ptr;
  auto x509 = d2i_X509(null, cast(const(ubyte)**)&ptr, cast(long)raw.length);
  auto outBio = BIO_new(BIO_s_mem());
  EVP_PKEY *pkey;
  pkey = X509_get_pubkey(x509);
  PEM_write_bio_PUBKEY(outBio, pkey);
  auto pSize = BIO_pending(outBio);
  auto output = new ubyte[pSize];
  BIO_read(outBio, output.ptr, pSize);
  X509_free(x509);
  BIO_free(outBio);
  EVP_PKEY_free(pkey);
  return cast(string)output;
}

auto enforceNonNull(T)(T* t) {
  import std.exception : enforce;
  enforce(t !is null, "expect non null");
  return t;
}

import deimos.openssl.rsa;
extern(C) int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
string extractPublicKeyFromModulusAndExponent(string modulus, string exponent) @trusted {
  import deimos.openssl.ssl;
  import deimos.openssl.pem;
  import deimos.openssl.rsa;
  import deimos.openssl.hmac;
  import deimos.openssl.err;
  auto n = Base64URLNoPadding.decode(modulus);
  auto e = Base64URLNoPadding.decode(exponent);
  RSA* rsa = RSA_new();
  RSA_set0_key(rsa,
               
               BN_bin2bn(n.ptr, cast(int)n.length, null).enforceNonNull,
               BN_bin2bn(e.ptr, cast(int)e.length, null).enforceNonNull,
               null
               ).opensslIsValid();
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(pkey, rsa).opensslIsValid();
  auto outBio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(outBio, pkey).opensslIsValid();
  auto pSize = BIO_pending(outBio);
  auto output = new ubyte[pSize];
  BIO_read(outBio, output.ptr, pSize);
  BIO_free(outBio);
  EVP_PKEY_free(pkey);
  RSA_free(rsa);
  return cast(string)output;
}

import deimos.openssl.ec;
extern(C)
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x,
                                             BIGNUM *y);

void opensslIsValid(ulong err) {
  import std.exception : enforce;
  enforce(err == 1, "openssl error");
}

string extractPublicKeyFromXYCoords(string curve, string x, string y) @trusted {
  import deimos.openssl.ssl;
  import deimos.openssl.pem;
  import deimos.openssl.rsa;
  import deimos.openssl.hmac;
  import deimos.openssl.err;
  import std.exception : enforce;
  int nid;
  switch(curve) {
  case "P-256": nid = NID_X9_62_prime256v1; break;
  case "P-384": nid = NID_secp384r1; break;
  case "P-521": nid = NID_secp521r1; break;
  default: throw new Exception("Unknown curve nid "~curve);
  }
  auto xCoord = Base64URLNoPadding.decode(x);
  auto yCoord = Base64URLNoPadding.decode(y);
  auto bigX = BN_bin2bn(xCoord.ptr, cast(int)xCoord.length, null);
  auto bigY = BN_bin2bn(yCoord.ptr, cast(int)yCoord.length, null);
  EC_KEY* ecKey = EC_KEY_new_by_curve_name(nid);
  EC_KEY_set_public_key_affine_coordinates(ecKey, bigX, bigY).opensslIsValid();
  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_set1_EC_KEY(pkey, ecKey).opensslIsValid();
  auto outBio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(outBio, pkey).opensslIsValid();
  auto pSize = BIO_pending(outBio);
  auto output = new ubyte[pSize];
  BIO_read(outBio, output.ptr, pSize);
  BIO_free(outBio);
  EVP_PKEY_free(pkey);
  EC_KEY_free(ecKey);
  return cast(string)output;
}

JWT validateJwt(JWT jwt) @safe {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime();
  if (auto exp = "exp" in jwt.json) {
    if (now >= exp.integer) {
      throw new Exception("Token expired");
    }
  }
  if (auto nbf = "nbf" in jwt.json) {
    if (nbf.integer > now) {
      throw new Exception("Token not valid yet");
    }
  }
  return jwt;
}

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


// auto extractAuth0Jwt(string scp)(HTTPServerRequest req, HTTPServerResponse res) {
//   try {
//     return req.extractJWTCookie!"access_token".map!(jwt=>decodeAuth0Jwt(jwt)).tee!(validateJwt!scp).array.toOption;
//   } catch (Exception e) {
//     res.redirect("https://dev-portal.coin.nl/authenticator/v1/");
//     return none!JSONValue;
//   }
// }
