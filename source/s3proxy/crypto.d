module s3proxy.crypto;

import jwtd.jwt : JWTAlgorithm;
import deimos.openssl.ssl;
import deimos.openssl.pem;
import deimos.openssl.rsa;
import deimos.openssl.hmac;
import deimos.openssl.err;
import deimos.openssl.ec;
import std.exception : enforce;

extern(C) int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
extern(C) int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y);

bool verifySignature(ubyte[] signature, string signing_input, string key, JWTAlgorithm algo = JWTAlgorithm.HS256) {
  import jwtd.jwt;
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

string extractPublicKeyFromCert(string cert) @trusted {
  import std.base64 : Base64;
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

string extractPublicKeyFromModulusAndExponent(string modulus, string exponent) @trusted {
  import std.base64 : Base64URLNoPadding;
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

string extractPublicKeyFromXYCoords(string curve, string x, string y) @trusted {
  import std.base64 : Base64URLNoPadding;
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

private void opensslIsValid(ulong err) {
  import std.exception : enforce;
  enforce(err == 1, "openssl error");
}

private auto enforceNonNull(T)(T* t) {
  import std.exception : enforce;
  enforce(t !is null, "expect non null");
  return t;
}
