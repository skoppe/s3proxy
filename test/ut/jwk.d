module jwk;

import s3proxy.jwk;
import unit_threaded;
import std.json;

@("parseJwksKeys.RSA")
@safe unittest {
  `{"keys":[{"kty":"RSA","kid":"yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU","e":"AQAB","n":"z4P2EC4hwKOwMwb6fpwHa_f-G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcLhhKHiRDEX0i-aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa033k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8krCPCR1DYQprGPmMTjC9bCRaQ_Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J-JEVKL4TSgxJEgGxa239WbWHgu7SR_dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XXlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti-rZ_UFdotFVQNHwaJSvCXe3-mk6xGdLpTlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe_YK37fPp_7ozEvGobtnrtlW697RWzO4IO0h-pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFmkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408Wk3pA9nfaGijWnuQ_f7mx8QDJ41tw5do89Cz-eY4OeBGe3VGleEw0BE2A_bAdxEopyjQhj7Yb8c2RLMk8sM0Njc","use":"sig","alg":"RS256"}]}`.parseJwksKeys().should == JWKS([JWK("RS256", "yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU", "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz4P2EC4hwKOwMwb6fpwH\na/f+G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcL\nhhKHiRDEX0i+aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa0\n33k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8k\nrCPCR1DYQprGPmMTjC9bCRaQ/Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J+JEVKL4T\nSgxJEgGxa239WbWHgu7SR/dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XX\nlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti+rZ/UFdotFVQNHwaJSvCXe3+mk6xGdLpT\nlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe/YK37fPp\n/7ozEvGobtnrtlW697RWzO4IO0h+pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFm\nkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408\nWk3pA9nfaGijWnuQ/f7mx8QDJ41tw5do89Cz+eY4OeBGe3VGleEw0BE2A/bAdxEo\npyjQhj7Yb8c2RLMk8sM0NjcCAwEAAQ==\n-----END PUBLIC KEY-----\n")]);
}

@("parseJwksKeys.EC")
@safe unittest {
  `{"keys":[{"kty":"EC","kid":"yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","crv":"P-256","use":"sig","alg":"RS256"}]}`.parseJwksKeys().should == JWKS([JWK("RS256", "yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----\n")]);
}

JWK testJwk() @safe {
  return JWK("RS256","MzU4OEI1MzVDQTg4MzQ4ODU1RUVFRTIzMjk3MjM1NTA0NDg1OEEyOA","-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJaQ0Q9C6h/PRa9VlS01\ndoPjNMe+3wSuYMm2HVbIt2Q3TnRIBqFdnPTY2WGMKgaml2vwSp/vaevs0RakP4n4\n0esXizNLVrIAFT84XUt4mvI20pj56X9+l5lkhSEWwY6luT8TkE9fYuCxUMRIhO8J\n17li0KQN50KjRHteM1VkgleUJGbtjXkkuc91JSFGaE8uAAsY1DH9xjxlkGQ01gqO\nq8qaQSRIw3JNwbZTkdT5wFLyF4KHZ1Xb496FN30R6TnxJwMyizTHyqCqEJVGL4cK\nmOzf6lnH7fE1xQW7gYCcXY26AGo3lMFezC8IsFImVSQivwK+1fggj2+gp/jFRzJY\nUQIDAQAB\n-----END PUBLIC KEY-----\n");
}

@("validateRawJwtSignature")
@safe unittest {
  import jwt : rawTestJwt;
  rawTestJwt().validateRawJwtSignature(JWKS([testJwk()])).shouldNotThrow();
  rawTestJwt().validateRawJwtSignature(JWKS()).shouldThrow();
  rawTestJwt().validateRawJwtSignature(JWKS([JWK("RS256")])).shouldThrow();
}

@("JWKSCache.populated")
unittest {
  testJWKSCache().get(testIssuer).keys[0].alg.should == "RS256";
}

@("JWKSCache.empty")
unittest {
    import concurrency.stream : transform, take, toList;
    import concurrency.sender;
    import concurrency.operations : via, then, whenAll;
    import concurrency.thread;
    import concurrency;
    import std.conv : to;
    import s3proxy.http;
    import std.socket : Socket, AddressFamily, SocketType, parseAddress;
    import s3proxy.utils : openRandomSocket, s3Client, localstack;
    import s3proxy.server;
    import std.format : format;

    auto socket = openRandomSocket();
    auto server = listenServer(socket.handle);

    shared ushort port = socket.port;
    auto api = server.transform((socket_t t) shared @trusted {
        auto socket = new Socket(t, AddressFamily.INET);
        ubyte[512] scopedBuffer;
        auto req = parseHttpRequest(socket, scopedBuffer[]);
        if (req.path == "/.well-known/openid-configuration") {
          string msg = `{"jwks_uri":"http://0.0.0.0:%s/.well-known/jwks.json"}`.format(port);
          socket.sendHttpResponse(200, ["content-type": "application/json", "connection": "close", "content-length": msg.length.to!string ], msg);
          socket.close();
          return true;
        }
        if (req.path == "/.well-known/jwks.json") {
          string msg = `{"keys":[{"kty":"EC","kid":"yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","crv":"P-256","use":"sig","alg":"RS256"}]}`;
          socket.sendHttpResponse(200, ["content-type": "application/json", "connection": "close", "content-length": msg.length.to!string ], msg);
          socket.close();
          return true;
        }
        socket.send("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n");
        socket.close();
        return false;
      }).take(2).toList().via(ThreadSender());
  
    auto fetchThem = just(socket.port).then((ushort port) shared @trusted {
        import requests;
        import std.conv : to;
        import core.thread;
        import core.time;
        Thread.sleep(50.msecs);
        JWKSCache c;
        return c.get("http://0.0.0.0:"~port.to!string);
      });

    auto result = whenAll(api, fetchThem).syncWait();
    result.assumeOk;
    result.value[1].should == JWKS([JWK("RS256", "yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----\n")]);

}

@("generateOIDCCredentials")
unittest {
  import s3proxy.auth : WebIdentityAuthentication, OIDCAuthenticationProvider;
  import s3proxy.proxy : generateOIDCCredentials;
  import s3proxy.config;
  auto webAuth = WebIdentityAuthentication("name","secret",1234);
  auto config = Config();
  config.oidcProviders = [OIDCAuthenticationProvider(testIssuer,["my-scope"], webAuth)];
  auto cache = testJWKSCache();
  auto jwt = testJWT(testIssuer, ["my-scope"]);

  generateOIDCCredentials(config, cache, jwt).shouldNotThrow;
}

string testJWT(string iss, string[] scopes) {
  import jwtd.jwt;
  import std.string : join;
  import crypto : testRSAPrivateKey;
  JSONValue payload;
  payload["iss"] = iss;
  payload["scope"] = scopes.join(" ");

  JSONValue header;
  header["kid"] = testKid;

  return encode(payload,testRSAPrivateKey,JWTAlgorithm.RS256, header);
}

enum testIssuer = "myks";
enum testKid = "kid";

JWKSCache testJWKSCache() {
  import crypto : testRSAPublicKey;
  return JWKSCache([testIssuer:JWKS([JWK("RS256",testKid,testRSAPublicKey)])]);
}
