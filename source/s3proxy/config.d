module s3proxy.config;

import mir.algebraic : Algebraic;

struct Server {
  string name, endpoint, key, secret, region;
}

struct RawAuthentication {
  string name, type, key, secret;
}

enum Permission : string {
  read = "read",
  write = "write"
}

struct BucketAccess {
  Permission[] permissions;
  string auth;
}

struct RawBucket {
  string name, server;
  BucketAccess[] access;
}

struct RawConfig {
  Server[] servers;
  RawAuthentication[] authentications;
  RawBucket[] buckets;
}

RawConfig loadConfig(string content) @trusted {
  import toml_foolery;
  return content.parseToml!RawConfig;
}

struct CredentialAuthenticator {
  enum type = "credentials";
  string name, key, secret;
  static typeof(this) from(RawAuthentication auth) @safe pure {
    return CredentialAuthenticator(auth.name, auth.key, auth.secret);
  }
  bool matches(string key) @safe pure {
    return this.key == key;
  }
}

alias Authenticator = Algebraic!(CredentialAuthenticator);

struct Authentication {
  Permission[] permissions;
  Authenticator authenticator;
}

struct Bucket {
  string name;
  Server server;
  Authentication[] auth;
}

struct Config {
  Bucket[] buckets;
}

Config parseConfig(RawConfig raw) @safe pure {
  import std.algorithm : map;
  import std.array : array;
  auto buckets = raw.buckets.map!((b){
      auto server = raw.locateServer(b.server);
      auto auths = b.access.map!((a){
          auto authenticator = raw.locateAuth(a.auth).decodeAuth();
          return Authentication(a.permissions, authenticator);
        }).array();
      return Bucket(b.name, server, auths);
    }).array();
  return Config(buckets);
}

Server locateServer(ref RawConfig config, string name) @safe pure {
  import std.algorithm : find, filter;
  import std.range : empty, front, walkLength;
  auto range = config.servers.find!(s => s.name == name);
  if (range.empty)
    throw new Exception("Config error, cannot find server '"~name~"'");
  if (range.filter!(s => s.name == name).walkLength > 1)
    throw new Exception("Config error, duplicate servers '"~name~"'");
  return range.front();
}

RawAuthentication locateAuth(ref RawConfig config, string name) @safe pure {
  import std.algorithm : find, filter;
  import std.range : empty, front, walkLength;
  auto range = config.authentications.find!(s => s.name == name);
  if (range.empty)
    throw new Exception("Config error, cannot find authentication '"~name~"'");
  if (range.filter!(s => s.name == name).walkLength > 1)
    throw new Exception("Config error, duplicate authentication '"~name~"'");
  return range.front();
}

Authenticator decodeAuth(RawAuthentication auth) @safe pure {
  static foreach(T; Authenticator.AllowedTypes) {
    if (T.type == auth.type) {
      return Authenticator(T.from(auth));
    }
  }
  if (auth.type == "" || auth.type == null)
    throw new Exception("Config error, authentication '"~auth.name~"' missing type field");
  throw new Exception("Config error, unknown authentication '"~auth.type~"'");
}
