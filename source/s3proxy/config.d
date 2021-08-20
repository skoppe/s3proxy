module s3proxy.config;

import mir.algebraic : Algebraic;
import std.experimental.logger : LogLevel;
import s3proxy.auth;
import toml_foolery : TomlName;

struct Server {
  string name, endpoint, key, secret, region = "us-east-1";
}

struct RawAuthentication {
  string name, type, key, secret;
  ulong expires;
}

struct BucketAccess {
  Permission[] permissions;
  string auth;
}

struct RawBucket {
  string name, server;
  BucketAccess[] access;
}

struct RawOAuthAuthenticationProvider {
  string endpoint;
  string[] scopes;
  string auth;
}

struct RawOIDCAuthenticationProvider {
  string issuer;
  string[] scopes;
  string auth;
}

struct RawConfig {
  LogLevel logging = LogLevel.error;
  @TomlName("server")
  Server[] servers;
  @TomlName("authentication")
  RawAuthentication[] authentications;
  @TomlName("bucket")
  RawBucket[] buckets;
  @TomlName("oauth")
  RawOAuthAuthenticationProvider[] oauthProviders;
  @TomlName("oidc")
  RawOIDCAuthenticationProvider[] oidcProviders;
}

RawConfig loadConfig(string content) @trusted {
  import toml_foolery;
  return content.parseToml!RawConfig;
}

struct Bucket {
  string name;
  Server server;
  Access[] access;
}

struct Config {
  LogLevel logging;
  Bucket[] buckets;
  OAuthAuthenticationProvider[] oauthProviders;
  OIDCAuthenticationProvider[] oidcProviders;
}

Config parseConfig(RawConfig raw) @safe {
  import std.algorithm : map;
  import std.array : array;
  auto buckets = raw.buckets.map!((b){
      auto server = raw.locateServer(b.server);
      auto accesses = b.access.map!((a){
          auto authentication = raw.locateAuth(a.auth).decodeAuth();
          return Access(a.permissions, authentication);
        }).array();
      return Bucket(b.name, server, accesses);
    }).array();
  auto oauthProviders = raw.oauthProviders.map!((provider){
      auto auth = raw.locateAuth(provider.auth).decodeAuth;
      return OAuthAuthenticationProvider(provider.endpoint, provider.scopes, auth.get!WebIdentityAuthentication);
    }).array();
  auto oidcProviders = raw.oidcProviders.map!((provider){
      auto auth = raw.locateAuth(provider.auth).decodeAuth;
      return OIDCAuthenticationProvider(provider.issuer, provider.scopes, auth.get!WebIdentityAuthentication);
    }).array();
  return Config(raw.logging, buckets, oauthProviders, oidcProviders);
}

CredentialAuthentication parseAuth(T)(RawAuthentication auth) if (is(T == CredentialAuthentication)) {
  return CredentialAuthentication(auth.name, auth.key, auth.secret);
}

WebIdentityAuthentication parseAuth(T)(RawAuthentication auth) if (is(T == WebIdentityAuthentication)) {
  return WebIdentityAuthentication(auth.name, auth.secret, auth.expires);
}

OAuthAuthenticationProvider parseAuthProvider(T)(RawAuthenticationProvider provider, Authentication auth) @safe pure if (is(T == OAuthAuthenticationProvider)) {
  return OAuthAuthenticationProvider(provider.endpoint, provider.scopes, auth);
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

Authentication decodeAuth(RawAuthentication auth) @safe {
  static foreach(T; Authentication.AllowedTypes) {
    if (T.type == auth.type) {
      return Authentication(auth.parseAuth!T);
    }
  }
  if (auth.type == "" || auth.type == null)
    throw new Exception("Config error, authentication '"~auth.name~"' missing type field");
  throw new Exception("Config error, unknown authentication '"~auth.type~"'");
}
