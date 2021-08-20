module jwt;


import s3proxy.jwt;
import unit_threaded;
import std.json;

RawJWT rawTestJwt() @safe {
  return decodeRawJwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik16VTRPRUkxTXpWRFFUZzRNelE0T0RVMVJVVkZSVEl6TWprM01qTTFOVEEwTkRnMU9FRXlPQSJ9.eyJodHRwOi8vYXBpLmNvaW4ubmwvdXNlcm5hbWUiOiJzLmtvcHBlQGNvaW4ubmwiLCJodHRwOi8vYXBpLmNvaW4ubmwvZ3JvdXBzIjpbIkNPSU4tU2VydmljZWRlc2siXSwiaHR0cDovL2FwaS5jb2luLm5sL3JvbGVzIjpbInNlcnZpY2VkZXNrIl0sImlzcyI6Imh0dHBzOi8vdmVyZW5pZ2luZ2NvaW4tZGV2LmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJhZHxWZXJlbmlnaW5nQ09JTnxiMzE5MmY2OS03ODM2LTQzNTctYWJiOC1kNjYxMTdmM2M0ZWIiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuY29pbi5ubC9jb25zdW1lci1hcGkiLCJodHRwczovL3ZlcmVuaWdpbmdjb2luLWRldi5ldS5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI5NjcxMzE1LCJleHAiOjE1Mjk2NzIyMTUsImF6cCI6InNuRnhuQjE4ZGdSb3hUQnRNQTRaWTZsd2JEMFBGN2Z4Iiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBwZXJtaXNzaW9ucyByb2xlcyBtYW5hZ2U6Z3JvdXBzIG1hbmFnZTp1c2VycyBtYW5hZ2U6Y29uc3VtZXJzIHZpZXc6YWNjZXNzIn0.nDORH_m_O3p_PjOW9Qc0cgBDShswtr0gofSw_Yz4d-lr63hFqD611_EvSRkezfGhmNiC-owfGQMmddZjgIOosmPBx-vrEg5A2x2yL-UjAyQA84K7DXw0YVkyXw0X2sVxTr-J1bmwCQy8q7QO6W4AIw3PFb-fVoJB_lkz_32wJWuXIsBtU-BAgF2xgojFzXgguIVZNOVoDHQBY6Qc7RnGpkB7RuZQIa0gAAtJNXwxc55vnYEESt2hiwxwqY6fvOijA6e6JCO5w3CLdD9BUm2KdbG2PHP_-jCJOtbvlpn6GpF3x6f_NkAVZ1xLJroUBLZbdhDx1-oJ-jOja7FHDppiFw");
}

JWK testJwk() @safe {
  return JWK("RS256","MzU4OEI1MzVDQTg4MzQ4ODU1RUVFRTIzMjk3MjM1NTA0NDg1OEEyOA","-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJaQ0Q9C6h/PRa9VlS01\ndoPjNMe+3wSuYMm2HVbIt2Q3TnRIBqFdnPTY2WGMKgaml2vwSp/vaevs0RakP4n4\n0esXizNLVrIAFT84XUt4mvI20pj56X9+l5lkhSEWwY6luT8TkE9fYuCxUMRIhO8J\n17li0KQN50KjRHteM1VkgleUJGbtjXkkuc91JSFGaE8uAAsY1DH9xjxlkGQ01gqO\nq8qaQSRIw3JNwbZTkdT5wFLyF4KHZ1Xb496FN30R6TnxJwMyizTHyqCqEJVGL4cK\nmOzf6lnH7fE1xQW7gYCcXY26AGo3lMFezC8IsFImVSQivwK+1fggj2+gp/jFRzJY\nUQIDAQAB\n-----END PUBLIC KEY-----\n");
}

@("decodeRawJwt.fails")
@safe unittest {
  import jwtd.jwt : JWTAlgorithm, encode;
  decodeRawJwt("").shouldThrow();
  decodeRawJwt("1.2").shouldThrow();
  decodeRawJwt("1.2.3").shouldThrow();
  decodeRawJwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik16VTRPRUkxTXpWRFFUZzRNelE0T0RVMVJVVkZSVEl6TWprM01qTTFOVEEwTkRnMU9FRXlPQSJ9.2.3").shouldThrow();
  rawTestJwt().shouldNotThrow();
}

@("decodeRawJwt.none.fail")
unittest {
  import jwtd.jwt : JWTAlgorithm, encode;
  encode(["iss":"me"],"",JWTAlgorithm.NONE).decodeRawJwt.shouldThrow();
}

@("decodeRawJwt.valid")
@safe unittest {
  import jwtd.jwt : JWTAlgorithm;
  auto rawJwt = rawTestJwt();
  rawJwt.alg.should == JWTAlgorithm.RS256;
  rawJwt.header["kid"].str.should == "MzU4OEI1MzVDQTg4MzQ4ODU1RUVFRTIzMjk3MjM1NTA0NDg1OEEyOA";
  rawJwt.payload["iss"].str.should == "https://verenigingcoin-dev.eu.auth0.com/";
  rawJwt.parts.length.should == 3;
}

@("validateRawJwtSignature")
@safe unittest {
  rawTestJwt().validateRawJwtSignature(JWKS([testJwk()])).shouldNotThrow();
  rawTestJwt().validateRawJwtSignature(JWKS()).shouldThrow();
  rawTestJwt().validateRawJwtSignature(JWKS([JWK("RS256")])).shouldThrow();
}

@("checkScopes")
unittest {
  auto jwt = JWT(q{{"scope":"manage:users manage:type"}}.parseJSON);
  jwt.checkScopes(["manage:users"]).shouldBeTrue;
  jwt.checkScopes(["manage:ty"]).shouldBeFalse;
  jwt.checkScopes([]).shouldBeTrue;
  jwt.checkScopes(["manage:users", "manage:type"]).shouldBeTrue;
}

@("extractPublicKeyFromCert")
unittest {
  extractPublicKeyFromCert("MIIDGTCCAgGgAwIBAgIJIDAsrXnJVoo7MA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMTH3ZlcmVuaWdpbmdjb2luLWRldi5ldS5hdXRoMC5jb20wHhcNMTcxMjA3MTQxODAyWhcNMzEwODE2MTQxODAyWjAqMSgwJgYDVQQDEx92ZXJlbmlnaW5nY29pbi1kZXYuZXUuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJaQ0Q9C6h/PRa9VlS01doPjNMe+3wSuYMm2HVbIt2Q3TnRIBqFdnPTY2WGMKgaml2vwSp/vaevs0RakP4n40esXizNLVrIAFT84XUt4mvI20pj56X9+l5lkhSEWwY6luT8TkE9fYuCxUMRIhO8J17li0KQN50KjRHteM1VkgleUJGbtjXkkuc91JSFGaE8uAAsY1DH9xjxlkGQ01gqOq8qaQSRIw3JNwbZTkdT5wFLyF4KHZ1Xb496FN30R6TnxJwMyizTHyqCqEJVGL4cKmOzf6lnH7fE1xQW7gYCcXY26AGo3lMFezC8IsFImVSQivwK+1fggj2+gp/jFRzJYUQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBT54964LEw0wKX5mZ3oRn/ibcP2zjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAHdGR9jHwFRPNB8ISMrxUbxs+oOUo+WPjO64TSeMXjlZWYs0hmSb5dbfPDP6aQpfwT5eChFefjtvGRsBWNwU8YtheGwQ/X53yCIOEZXf0Tb8O6KSpxhV5zlQZxjsReebmrE2jqYqlEYYV65SB+nUkn4IwI/DyKs3V6UA0mEbxZx56HyKnW5eER+yROGp7CsSOJsx0+z5wkgB9a46GwI5A3W5ZTKXKgbm8uN89KvfFppLqmhw3tMSGCTBW37++Z4/tpruUdk8vHEDaJ+ZaasTMEJcP0M/K/uj69+3CWFZ9hWEhagfKK0BwuhiHb/TqdQsKOb5dvccgTsOoSjSMVAQqCk=").shouldEqual("-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJaQ0Q9C6h/PRa9VlS01
doPjNMe+3wSuYMm2HVbIt2Q3TnRIBqFdnPTY2WGMKgaml2vwSp/vaevs0RakP4n4
0esXizNLVrIAFT84XUt4mvI20pj56X9+l5lkhSEWwY6luT8TkE9fYuCxUMRIhO8J
17li0KQN50KjRHteM1VkgleUJGbtjXkkuc91JSFGaE8uAAsY1DH9xjxlkGQ01gqO
q8qaQSRIw3JNwbZTkdT5wFLyF4KHZ1Xb496FN30R6TnxJwMyizTHyqCqEJVGL4cK
mOzf6lnH7fE1xQW7gYCcXY26AGo3lMFezC8IsFImVSQivwK+1fggj2+gp/jFRzJY
UQIDAQAB
-----END PUBLIC KEY-----
");
}

// @("Decode auth0 jwt")
// unittest {
//   decodeAuth0Jwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik16VTRPRUkxTXpWRFFUZzRNelE0T0RVMVJVVkZSVEl6TWprM01qTTFOVEEwTkRnMU9FRXlPQSJ9.eyJodHRwOi8vYXBpLmNvaW4ubmwvdXNlcm5hbWUiOiJzLmtvcHBlQGNvaW4ubmwiLCJodHRwOi8vYXBpLmNvaW4ubmwvZ3JvdXBzIjpbIkNPSU4tU2VydmljZWRlc2siXSwiaHR0cDovL2FwaS5jb2luLm5sL3JvbGVzIjpbInNlcnZpY2VkZXNrIl0sImlzcyI6Imh0dHBzOi8vdmVyZW5pZ2luZ2NvaW4tZGV2LmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJhZHxWZXJlbmlnaW5nQ09JTnxiMzE5MmY2OS03ODM2LTQzNTctYWJiOC1kNjYxMTdmM2M0ZWIiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuY29pbi5ubC9jb25zdW1lci1hcGkiLCJodHRwczovL3ZlcmVuaWdpbmdjb2luLWRldi5ldS5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI5NjcxMzE1LCJleHAiOjE1Mjk2NzIyMTUsImF6cCI6InNuRnhuQjE4ZGdSb3hUQnRNQTRaWTZsd2JEMFBGN2Z4Iiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBwZXJtaXNzaW9ucyByb2xlcyBtYW5hZ2U6Z3JvdXBzIG1hbmFnZTp1c2VycyBtYW5hZ2U6Y29uc3VtZXJzIHZpZXc6YWNjZXNzIn0.nDORH_m_O3p_PjOW9Qc0cgBDShswtr0gofSw_Yz4d-lr63hFqD611_EvSRkezfGhmNiC-owfGQMmddZjgIOosmPBx-vrEg5A2x2yL-UjAyQA84K7DXw0YVkyXw0X2sVxTr-J1bmwCQy8q7QO6W4AIw3PFb-fVoJB_lkz_32wJWuXIsBtU-BAgF2xgojFzXgguIVZNOVoDHQBY6Qc7RnGpkB7RuZQIa0gAAtJNXwxc55vnYEESt2hiwxwqY6fvOijA6e6JCO5w3CLdD9BUm2KdbG2PHP_-jCJOtbvlpn6GpF3x6f_NkAVZ1xLJroUBLZbdhDx1-oJ-jOja7FHDppiFw").toString().shouldEqual(q{{"aud":["https://api.coin.nl/consumer-api","https://verenigingcoin-dev.eu.auth0.com/userinfo"],"azp":"snFxnB18dgRoxTBtMA4ZY6lwbD0PF7fx","exp":1529672215,"http://api.coin.nl/groups":["COIN-Servicedesk"],"http://api.coin.nl/roles":["servicedesk"],"http://api.coin.nl/username":"s.koppe@coin.nl","iat":1529671315,"iss":"https://verenigingcoin-dev.eu.auth0.com/","scope":"openid profile permissions roles manage:groups manage:users manage:consumers view:access","sub":"ad|VerenigingCOIN|b3192f69-7836-4357-abb8-d66117f3c4eb"}}.replace("/","\\/"));
// }


@("validateJwt.basic")
@safe unittest {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime() - 10;
  auto jwt = JWT(q{{}}.parseJSON);
  jwt.validateJwt().shouldNotThrow();
}

@("validateJwt.exp.expired")
@safe unittest {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime() - 10;
  auto jwt = JWT(q{{}}.parseJSON);
  jwt.json["exp"] = now;
  jwt.validateJwt().shouldThrow();
}

@("validateJwt.exp.valid")
@safe unittest {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime() - 10;
  auto jwt = JWT(q{{}}.parseJSON);
  jwt.json["exp"] = now + 20;
  jwt.validateJwt().shouldNotThrow();
}

@("validateJwt.nbf.invalid")
@safe unittest {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime() - 10;
  auto jwt = JWT(q{{}}.parseJSON);
  jwt.json["nbf"] = now + 20;
  jwt.validateJwt().shouldThrow();
}

@("validateJwt.nbf.valid")
@safe unittest {
  import std.datetime.systime : SysTime, Clock;
  auto now = Clock.currTime().toUnixTime() - 10;
  auto jwt = JWT(q{{}}.parseJSON);
  jwt.json["nbf"] = now - 20;
  jwt.validateJwt().shouldNotThrow();
}

@("extractPublicKeyFromModulusAndExponent")
@safe unittest {
  extractPublicKeyFromModulusAndExponent("z4P2EC4hwKOwMwb6fpwHa_f-G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcLhhKHiRDEX0i-aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa033k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8krCPCR1DYQprGPmMTjC9bCRaQ_Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J-JEVKL4TSgxJEgGxa239WbWHgu7SR_dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XXlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti-rZ_UFdotFVQNHwaJSvCXe3-mk6xGdLpTlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe_YK37fPp_7ozEvGobtnrtlW697RWzO4IO0h-pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFmkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408Wk3pA9nfaGijWnuQ_f7mx8QDJ41tw5do89Cz-eY4OeBGe3VGleEw0BE2A_bAdxEopyjQhj7Yb8c2RLMk8sM0Njc", "AQAB").should == `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz4P2EC4hwKOwMwb6fpwH
a/f+G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcL
hhKHiRDEX0i+aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa0
33k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8k
rCPCR1DYQprGPmMTjC9bCRaQ/Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J+JEVKL4T
SgxJEgGxa239WbWHgu7SR/dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XX
lk9vHNr1Dnuhop3rJaEKCMvuZEDZCti+rZ/UFdotFVQNHwaJSvCXe3+mk6xGdLpT
lRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe/YK37fPp
/7ozEvGobtnrtlW697RWzO4IO0h+pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFm
kTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408
Wk3pA9nfaGijWnuQ/f7mx8QDJ41tw5do89Cz+eY4OeBGe3VGleEw0BE2A/bAdxEo
pyjQhj7Yb8c2RLMk8sM0NjcCAwEAAQ==
-----END PUBLIC KEY-----
`
;
}

@("parseJwksKeys.RSA")
@safe unittest {
  `{"keys":[{"kty":"RSA","kid":"yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU","e":"AQAB","n":"z4P2EC4hwKOwMwb6fpwHa_f-G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcLhhKHiRDEX0i-aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa033k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8krCPCR1DYQprGPmMTjC9bCRaQ_Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J-JEVKL4TSgxJEgGxa239WbWHgu7SR_dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XXlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti-rZ_UFdotFVQNHwaJSvCXe3-mk6xGdLpTlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe_YK37fPp_7ozEvGobtnrtlW697RWzO4IO0h-pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFmkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408Wk3pA9nfaGijWnuQ_f7mx8QDJ41tw5do89Cz-eY4OeBGe3VGleEw0BE2A_bAdxEopyjQhj7Yb8c2RLMk8sM0Njc","use":"sig","alg":"RS256"}]}`.parseJwksKeys().should == JWKS([JWK("RS256", "yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU", "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz4P2EC4hwKOwMwb6fpwH\na/f+G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcL\nhhKHiRDEX0i+aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa0\n33k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8k\nrCPCR1DYQprGPmMTjC9bCRaQ/Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J+JEVKL4T\nSgxJEgGxa239WbWHgu7SR/dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XX\nlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti+rZ/UFdotFVQNHwaJSvCXe3+mk6xGdLpT\nlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe/YK37fPp\n/7ozEvGobtnrtlW697RWzO4IO0h+pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFm\nkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408\nWk3pA9nfaGijWnuQ/f7mx8QDJ41tw5do89Cz+eY4OeBGe3VGleEw0BE2A/bAdxEo\npyjQhj7Yb8c2RLMk8sM0NjcCAwEAAQ==\n-----END PUBLIC KEY-----\n")]);
}

@("parseJwksKeys.EC")
@safe unittest {
  `{"keys":[{"kty":"EC","kid":"yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","crv":"P-256","use":"sig","alg":"RS256"}]}`.parseJwksKeys().should == JWKS([JWK("RS256", "yoiRNim8cP2xfhIpL9auDl20QQNXAwG8W_ANzWUbPeU", "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----\n")]);
}

@("extractPublicKeyFromXYCoords")
@safe unittest {
  auto x = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
  auto y = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
  extractPublicKeyFromXYCoords("P-256", x,y).should == "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A\niTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==\n-----END PUBLIC KEY-----\n";
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

@("validateRawJwtSignature.gitlab")
unittest {
  decodeRawJwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InlvaVJOaW04Y1AyeGZoSXBMOWF1RGwyMFFRTlhBd0c4V19BTnpXVWJQZVUifQ.eyJpc3MiOiJodHRwczovL2dpdC5zeW1tZXRyeS5kZXYiLCJzdWIiOiI3MCIsImF1ZCI6ImZkOGQwNGY1NmUzYTQ3OWIzMmMxNjlkNTg4NDE4ZmE4NjkzZjVkMzM4ZDlkNDUwOWRkZTQ2M2M2MDlhMTUyZjQiLCJleHAiOjE2MjkzOTk0NjQsImlhdCI6MTYyOTM5OTM0NCwiYXV0aF90aW1lIjoxNjI5Mjc5MjM5LCJzdWJfbGVnYWN5IjoiOGI5NTY1NmZlZDdhZDY4M2FhYmNlNDBlZGI5OTIzOGQzYzdlYTRmNGE3OTdkYjdlZGMzZmM5ZTE4NGRiYTYzOCJ9.CHHvDTiNkpO1xyppWK030bZg8Ynr9YTVYKRS2gjiaONWRR2Jc4REHJEpZsUpWPokHAhIP4nz5AjmZA3GjbId28s_80Z_GsunDK9-jkbgQxiHOoLtC5_AEOxuebq3EIv0k2OPvN97CXA-sA9U21f8gu8CdwfNNznhXv2OfcHWbfD5TIf9sMxHoXhH8LWHA0qrENZnFDXjfU32m44PwE95j4lTscWgCpg-yFCp-kDqezGzT4OkGx5D2YZlnXx8_B2xtBpLttuvYWetJYrf3JFPcfgqndzdy5FvfZHY2IBRxGJBjcIjtZMNG6XZ72hn3-nr8CGtdi7gRpM858oK5R0oa8Rr0y4vgGnH_4UaBbXYKWrZHAcuKdD4oYmt-YEqaQVg0zdWE187QoYXy3X5VnUO-ImbTWmRUUOo1E3eDC6EqUiHTL5daDsfYKKkUzwBMXdXAUX3yyjij4-toKrITZzkAkdhy-Ep6bsc8D6jq9WBI6T4gAlL8gNDorq6oasULfz5fw8lmfPoNfdRLeLqhSS7pJCNfzsKCytvF2kSHDc3ugTZA8vkyBOArFZjCJRu5bTpV1OtT2hzbiURx7rV4mM0Sr1WJ9L9atvTxHDMOHeU43cIGgm-LT9owzgKj129KX0VFE1lUZsNs7AKVzkMdJbeg9VyW_VR9v_DYTGNfhRyxoA")
    .validateRawJwtSignature("-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz4P2EC4hwKOwMwb6fpwH\na/f+G2w28ucgvGOQqZalzVPNkIuo3y4w46Nlkl8jMPO3vdJt3GAm7TpFD2JCNmcL\nhhKHiRDEX0i+aYHqPeRi9PGm0moBL7jWL0lLvDpRJiIFE3u2PiuOXb2kQLoxvVa0\n33k8C3nMr2oALnaM8MkXbds3mKBixXOV4oBkVhxXLrZBhtZbJcMfnq0Jwa80pD8k\nrCPCR1DYQprGPmMTjC9bCRaQ/Nlzn6QOuGNLb0YrKEH2pxvoqcgjuU8J+JEVKL4T\nSgxJEgGxa239WbWHgu7SR/dV7eh9zlb2AMindr1M4o6ADXDpket2agCXPXsgq9XX\nlk9vHNr1Dnuhop3rJaEKCMvuZEDZCti+rZ/UFdotFVQNHwaJSvCXe3+mk6xGdLpT\nlRbTqrneonqkpW9lDZDfdzuVk2qQ4apccVzJaoCjN4RdpThrxwfOJYZe/YK37fPp\n/7ozEvGobtnrtlW697RWzO4IO0h+pq1FX701zTq6wjDbWNoFtAfCj6YID5qH8aFm\nkTurABLjYAD0cMEIY0AhVDZgcbvT42aD4UTyVqCBWjV5bdnZd6vWexcicA6z1408\nWk3pA9nfaGijWnuQ/f7mx8QDJ41tw5do89Cz+eY4OeBGe3VGleEw0BE2A/bAdxEo\npyjQhj7Yb8c2RLMk8sM0NjcCAwEAAQ==\n-----END PUBLIC KEY-----\n");
}

@("validateRawJwtSignature.oauth")
unittest {
  auto jwt = decodeRawJwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik16VTRPRUkxTXpWRFFUZzRNelE0T0RVMVJVVkZSVEl6TWprM01qTTFOVEEwTkRnMU9FRXlPQSJ9.eyJodHRwOi8vYXBpLmNvaW4ubmwvdXNlcm5hbWUiOiJzLmtvcHBlQGNvaW4ubmwiLCJodHRwOi8vYXBpLmNvaW4ubmwvZ3JvdXBzIjpbIkNPSU4tU2VydmljZWRlc2siXSwiaHR0cDovL2FwaS5jb2luLm5sL3JvbGVzIjpbInNlcnZpY2VkZXNrIl0sImlzcyI6Imh0dHBzOi8vdmVyZW5pZ2luZ2NvaW4tZGV2LmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJhZHxWZXJlbmlnaW5nQ09JTnxiMzE5MmY2OS03ODM2LTQzNTctYWJiOC1kNjYxMTdmM2M0ZWIiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuY29pbi5ubC9jb25zdW1lci1hcGkiLCJodHRwczovL3ZlcmVuaWdpbmdjb2luLWRldi5ldS5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI5NjcxMzE1LCJleHAiOjE1Mjk2NzIyMTUsImF6cCI6InNuRnhuQjE4ZGdSb3hUQnRNQTRaWTZsd2JEMFBGN2Z4Iiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBwZXJtaXNzaW9ucyByb2xlcyBtYW5hZ2U6Z3JvdXBzIG1hbmFnZTp1c2VycyBtYW5hZ2U6Y29uc3VtZXJzIHZpZXc6YWNjZXNzIn0.nDORH_m_O3p_PjOW9Qc0cgBDShswtr0gofSw_Yz4d-lr63hFqD611_EvSRkezfGhmNiC-owfGQMmddZjgIOosmPBx-vrEg5A2x2yL-UjAyQA84K7DXw0YVkyXw0X2sVxTr-J1bmwCQy8q7QO6W4AIw3PFb-fVoJB_lkz_32wJWuXIsBtU-BAgF2xgojFzXgguIVZNOVoDHQBY6Qc7RnGpkB7RuZQIa0gAAtJNXwxc55vnYEESt2hiwxwqY6fvOijA6e6JCO5w3CLdD9BUm2KdbG2PHP_-jCJOtbvlpn6GpF3x6f_NkAVZ1xLJroUBLZbdhDx1-oJ-jOja7FHDppiFw")
    .validateRawJwtSignature("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJaQ0Q9C6h/PRa9VlS01\ndoPjNMe+3wSuYMm2HVbIt2Q3TnRIBqFdnPTY2WGMKgaml2vwSp/vaevs0RakP4n4\n0esXizNLVrIAFT84XUt4mvI20pj56X9+l5lkhSEWwY6luT8TkE9fYuCxUMRIhO8J\n17li0KQN50KjRHteM1VkgleUJGbtjXkkuc91JSFGaE8uAAsY1DH9xjxlkGQ01gqO\nq8qaQSRIw3JNwbZTkdT5wFLyF4KHZ1Xb496FN30R6TnxJwMyizTHyqCqEJVGL4cK\nmOzf6lnH7fE1xQW7gYCcXY26AGo3lMFezC8IsFImVSQivwK+1fggj2+gp/jFRzJY\nUQIDAQAB\n-----END PUBLIC KEY-----\n");
  jwt.json["iss"].str.should == "https://verenigingcoin-dev.eu.auth0.com/";
  jwt.json["azp"].str.should == "snFxnB18dgRoxTBtMA4ZY6lwbD0PF7fx";
}

string testJWT(string iss, string[] scopes) {
  import jwtd.jwt;
  import std.string : join;
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
  return JWKSCache([testIssuer:JWKS([JWK("RS256",testKid,testRSAPublicKey)])]);
}
    string testRSAPrivateKey = q"EOS
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq+e/dME9Mrklp8hvhzqoAq+CWCyOHQrsoMhyuqieTr3QfURt
UY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/zTDfEvDFjIVz2HffzTzriQ/q4nF2p
ZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu8KfUZjEA5U8Za5MpM4E6P624zMz+
N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5YxYQ+mpVvPrR5WZhfRCRET3whPC0kR
xy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+9eag7Df//GhHb8MlUUgAlTXnHhOL
f1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HOSQIDAQABAoIBAFtk48JUNpAwJVf1
1W3E/qwm2Zq9XXUNaM72oyCgI0Jj4mOnLKOvQmC75QQZX5IeaHyfhcklr9hdzNdS
yMu7bJO6FqujajvDq8o1GDOob8GKm/nuRfEhDotKRlo3c8cEWu1PZhudnbDfeiiY
gQyEnyQtZlxKc1p22mH6JG6QpwJRH5iaxaCcAY+zxXDf1NJcqLtlCQfPycLT8fPW
OFVUrtUnUG8DEm8V8r1oHh6UsCQsrQbB20qWJdiQxr9W2riw6eO/EnK9vsXXqRGz
rXyuaE2zZezgURthgVYiPpe+OrDyeUWdpn1Uoh0PrFzPtLVEjYpMmT5TpBkbhKBS
/4re050CgYEA4JmOwOXg99kedusy5cghsEXI3fN/fUaAj2nfP3rjJaLEiMOSm/mN
8CDGdoOKXmhk7w1up3v2AMAEyKbIdrMAVc/m9GiKNPuiONlHZW/xQGBil9MY84Nh
WUswg0fg70u4OnpfyYnbrnDPt+BpKIO0n5W6TzDs4iFogTlaky5B77cCgYEAw/A/
jZBIxyYUJgext7aoh/WY3d/gHmAyimk0gawQszIQF4248HGPm3ZTL8FoXAMCNFEA
t03sNubIhybS6bHz+gi2P/vNUGGrw3bdXW4geWoaZGwfDmKg0B/q7yOH3MhJ1oSh
mhImyN1QGPp3fctdaax78JnGTm5aXIBAc1d+Mf8CgYBAbq0OV6RHVgkwUl8CnnxT
pmFukvlDBiPBgLzj6Cwb0usQ1RJNHrWCatSkkS3z0X0LO05ATAaRxoRYz8f4jXeO
Jpt6CDeF5Z5vMp4R0qBiOIRwS8X/rfQSesiLEObNn2pVlF/AYIUeMQzWElH4pnf9
xCVzrHR4lt71G3AJgx61VwKBgQCraSDgAkp41kooHvENK+Fx15xc9f6F9Fgil/jU
PCf77B8By/zvdBlSwofxrjxSylsCU57RvXyZZvokqgU3ZnNu2HI/tVQfLuLpw7HS
i4YjUXw3QBNHLWdLy7Bmdmnj7uARp8QMGjcN3/azc2JXjTJyQO/IQ26lrIqmg5he
jzsaFwKBgBLI/WJkvP5IKCSE4zSCOtOMKMMXDEv3lH30O2z4syw2ET0ENAioQDwv
r1c/sFsyUoBwnLmJhwYxuveNBLYYNfgLFsJJvPd1Req+ni47e28qKn2iRG7GZvct
pkIt+dzxyAoauwspxEEiPpGjz91dvBSG9qLcqNQ+BF4X4byB9itQ
-----END RSA PRIVATE KEY-----
EOS";

string testRSAPublicKey = q"EOS
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+e/dME9Mrklp8hvhzqo
Aq+CWCyOHQrsoMhyuqieTr3QfURtUY+d9VV0NhfgSRrbzsYGodOV+suo5jr/zi/z
TDfEvDFjIVz2HffzTzriQ/q4nF2pZqfaS+ctqq6wIa5E05abW4mK6vz1Xnuqi1wu
8KfUZjEA5U8Za5MpM4E6P624zMz+N8C9k6LyNgE3Pr9eU+t7obZNZnQCLBF4g5Yx
YQ+mpVvPrR5WZhfRCRET3whPC0kRxy7f1dBxpxq9z6udfUP5S/UyUqlieMeC6Y8+
9eag7Df//GhHb8MlUUgAlTXnHhOLf1lUEqlWWcHxJc9stbgMsPCOlvkurQCV36HO
SQIDAQAB
-----END PUBLIC KEY-----
EOS";
