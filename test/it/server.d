module server;

import s3proxy.server;
import unit_threaded;
import std.socket : Socket, AddressFamily, SocketType, parseAddress;
import s3proxy.utils : openRandomSocket, s3Client, localstack;

@("socket.raw")
@safe unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import std.conv : to;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @safe {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[] buffer = new ubyte[256];
      auto size = socket.receive(buffer);
      socket.close();
      return buffer[0..size];
    }).take(1).toList().via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @safe {
      auto socket = new Socket(AddressFamily.INET, SocketType.STREAM);
      socket.connect(parseAddress("0.0.0.0", port));
      socket.send(cast(ubyte[])[1,2,3,4,5]);
      socket.close();
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.isOk.should == true;
  result.value[0].should == cast(ubyte[])[1,2,3,4,5];
}

@("socket.http")
@safe unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import std.conv : to;
  import s3proxy.http;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      socket.send("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
      socket.close();
      return true;
    }).take(1).toList().via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      import requests;
      import std.conv : to;
      return getContent("http://0.0.0.0:"~port.to!string).data;
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
  result.value[0][0].should == true;
  result.value[1].should == [104, 101, 108, 108, 111];
}

@("request.threadpool")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.stoptoken;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import std.conv : to;
  import s3proxy.http;

  auto sock = openListeningSocket("0.0.0.0", 0);
  auto server = listenServer(sock.trustedGet);
  auto socket = new Socket(sock.trustedGet, AddressFamily.INET);
  auto localAddr = socket.localAddress();
  auto port = localAddr.toPortString().to!ushort;
  auto pool = cast(shared)stdTaskPool(2);
  auto stopSource = new shared StopSource();

  static void handleConnection(socket_t t) @trusted {
    auto socket = new Socket(t, AddressFamily.INET);
    ubyte[512] scopedBuffer;
    auto req = parseHttpRequest(socket, scopedBuffer[]);
    socket.send("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
    socket.close();
  }

  static struct ConnectionReceiver {
    static struct NullScheduler {}
    shared StopSource stopSource;
    void setValue() @safe {}
    void setError(Exception e) nothrow @safe {}
    void setDone() nothrow @safe {}
    auto getStopToken() { return StopToken(stopSource); }
    auto getScheduler() { return NullScheduler(); }
  }

  auto readOne = server.transform((socket_t t) shared @trusted {
      just(t)
        .via(pool.getScheduler().schedule())
        .then(&handleConnection)
        .connectHeap(ConnectionReceiver(stopSource))
        .start();
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(port).then((ushort port) shared @trusted {
      import requests;
      import std.conv : to;
      return getContent("http://0.0.0.0:"~port.to!string).data;
    });

  auto result = whenAll(readOne, writeOne).syncWait(stopSource);
  result.assumeOk;
  result.value.should == [104, 101, 108, 108, 111];
}

@("api.proxy.upload")
@trusted unittest {
  import concurrency.stream : transform, take;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyUpload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      s3Client(port).upload("test-bucket", "my-file", cast(ubyte[])[1,2,3,4,5]);
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
}

@("api.proxy.list")
@trusted unittest {
  import concurrency.stream : transform, take;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyList(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      s3Client(port).list("test-bucket", "/", null, null, 100);
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
}

@("api.proxy.download")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.http;
  import s3proxy.proxy;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyDownload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      return s3Client(port).download("test-bucket", "my-file").responseHeaders["content-length"];
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
  result.value.should == "5";
}

@("api.proxy.info")
@trusted unittest {
  import concurrency.stream : transform, take, toList;
  import concurrency.sender;
  import concurrency.operations : via, then, whenAll;
  import concurrency.thread;
  import concurrency;
  import s3proxy.proxy;
  import s3proxy.http;

  auto socket = openRandomSocket();
  auto server = listenServer(socket.handle);

  auto readOne = server.transform((socket_t t) shared @trusted {
      auto socket = new Socket(t, AddressFamily.INET);
      ubyte[512] scopedBuffer;
      auto req = parseHttpRequest(socket, scopedBuffer[]);
      localstack().proxyDownload(req, socket);
    }).take(1).collect(() shared {}).via(ThreadSender());

  auto writeOne = just(socket.port).then((ushort port) shared @trusted {
      return s3Client(port).info("test-bucket", "my-file")["content-length"];
    });

  auto result = whenAll(readOne, writeOne).syncWait();
  result.assumeOk;
  result.value.should == "5";
}
