module app;

import s3proxy.server : socket_t;
import s3proxy.proxy : Proxy;

@safe void main() {
  import concurrency.thread : stdTaskPool;
  import concurrency : syncWait;
  import concurrency.nursery : Nursery;

  auto server = createServer("0.0.0.0", 8080);
  auto pool = cast(shared)stdTaskPool(8);
  auto nursery = new shared Nursery();

  auto api = createProxy("s3proxy.toml");

  auto runServer = server.collect((socket_t socket) shared @trusted {
      auto task = api.handleRequest(socket, pool.getScheduler);
      nursery.run(task);
    });

  nursery.run(runServer);
  nursery.syncWait().assumeOk;
}

auto handleRequest(Scheduler)(ref shared Proxy api, socket_t t, Scheduler scheduler) {
  import concurrency.sender : just;
  import concurrency.operations : via, withStopToken;
  return just(t).via(scheduler.schedule()).withStopToken(&api.handle);
}

auto createServer(string host, ushort port) @safe {
  import s3proxy.server : openListeningSocket, listenServer;

  auto socket = openListeningSocket(host, port).unwrap();
  return listenServer(socket);
}

auto createProxy(string configFile) @safe {
  import s3proxy.config;
  import std.experimental.logger : globalLogLevel;
  import std.file : readText;

  auto config = loadConfig(readText(configFile)).parseConfig();
  auto api = shared Proxy(config);

  globalLogLevel = config.logging;
  
  return api;
}
