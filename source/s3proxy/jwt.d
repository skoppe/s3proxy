module s3proxy.jwt;

import std.json;
import std.base64;
import std.range;
import std.algorithm;
import std.format : format;
import jwtd.jwt : JWTAlgorithm;
import s3proxy.crypto : verifySignature;

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

JWT validateRawJwtSignature(RawJWT jwt, string key) @trusted {
  import jwtd.jwt : VerifyException;
  auto signature = Base64URLNoPadding.decode(jwt.parts[2]);
	if(!verifySignature(signature, jwt.parts[0]~"."~jwt.parts[1], key, jwt.alg))
		throw new VerifyException("Signature is incorrect.");

  return JWT(jwt.payload);
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
