module jwt;


import s3proxy.jwt;
import unit_threaded;
import std.json;

RawJWT rawTestJwt() @safe {
  return decodeRawJwt("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik16VTRPRUkxTXpWRFFUZzRNelE0T0RVMVJVVkZSVEl6TWprM01qTTFOVEEwTkRnMU9FRXlPQSJ9.eyJodHRwOi8vYXBpLmNvaW4ubmwvdXNlcm5hbWUiOiJzLmtvcHBlQGNvaW4ubmwiLCJodHRwOi8vYXBpLmNvaW4ubmwvZ3JvdXBzIjpbIkNPSU4tU2VydmljZWRlc2siXSwiaHR0cDovL2FwaS5jb2luLm5sL3JvbGVzIjpbInNlcnZpY2VkZXNrIl0sImlzcyI6Imh0dHBzOi8vdmVyZW5pZ2luZ2NvaW4tZGV2LmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJhZHxWZXJlbmlnaW5nQ09JTnxiMzE5MmY2OS03ODM2LTQzNTctYWJiOC1kNjYxMTdmM2M0ZWIiLCJhdWQiOlsiaHR0cHM6Ly9hcGkuY29pbi5ubC9jb25zdW1lci1hcGkiLCJodHRwczovL3ZlcmVuaWdpbmdjb2luLWRldi5ldS5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI5NjcxMzE1LCJleHAiOjE1Mjk2NzIyMTUsImF6cCI6InNuRnhuQjE4ZGdSb3hUQnRNQTRaWTZsd2JEMFBGN2Z4Iiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBwZXJtaXNzaW9ucyByb2xlcyBtYW5hZ2U6Z3JvdXBzIG1hbmFnZTp1c2VycyBtYW5hZ2U6Y29uc3VtZXJzIHZpZXc6YWNjZXNzIn0.nDORH_m_O3p_PjOW9Qc0cgBDShswtr0gofSw_Yz4d-lr63hFqD611_EvSRkezfGhmNiC-owfGQMmddZjgIOosmPBx-vrEg5A2x2yL-UjAyQA84K7DXw0YVkyXw0X2sVxTr-J1bmwCQy8q7QO6W4AIw3PFb-fVoJB_lkz_32wJWuXIsBtU-BAgF2xgojFzXgguIVZNOVoDHQBY6Qc7RnGpkB7RuZQIa0gAAtJNXwxc55vnYEESt2hiwxwqY6fvOijA6e6JCO5w3CLdD9BUm2KdbG2PHP_-jCJOtbvlpn6GpF3x6f_NkAVZ1xLJroUBLZbdhDx1-oJ-jOja7FHDppiFw");
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

@("checkScopes")
unittest {
  auto jwt = JWT(q{{"scope":"manage:users manage:type"}}.parseJSON);
  jwt.checkScopes(["manage:users"]).shouldBeTrue;
  jwt.checkScopes(["manage:ty"]).shouldBeFalse;
  jwt.checkScopes([]).shouldBeTrue;
  jwt.checkScopes(["manage:users", "manage:type"]).shouldBeTrue;
}

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

