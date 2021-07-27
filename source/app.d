module app;

@safe void main() {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll, withStopToken;
  import concurrency.thread;
  import concurrency;
  import concurrency.nursery;
  import s3proxy.proxy;
  import s3proxy.http;
  import s3proxy.server;
  import s3proxy.config;
  import std.experimental.logger : globalLogLevel;
  import std.file : readText;

  auto socket = openListeningSocket("0.0.0.0", 8080).unwrap();
  auto server = listenServer(socket);
  auto pool = cast(shared)stdTaskPool(8);
  auto nursery = new shared Nursery();

  auto config = loadConfig(readText("s3proxy.toml")).parseConfig();
  auto api = shared Proxy(config);

  globalLogLevel = config.logging;

  auto runServer = server.collect((socket_t t) shared @trusted {
      nursery.run(just(t).via(pool.getScheduler().schedule()).withStopToken(&api.handle));
    });

  nursery.run(runServer);
  nursery.syncWait().assumeOk;
}
