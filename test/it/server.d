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

/+

the server is a stream of sockets,
for each socket_t it spits out we want to create a new Sender() and we want to start and await that somewhere

we probably have to connect it on the Heap and setup a simple receiver that holds a counter and it only completes if the counter is at zero and the stoptoken has been called

it is a little like a fork

connect(Receiver)(Receiver receiver) {
  auto op = server.collect((socket_t socket){
    just(socket).via(receiver.getScheduler.schedule()).then(dg).connectHeap(childReceiver(receiver)).start();
  }).connect(receiver);
  return op;
}

auto fork(Stream)(Stream stream) if (models!(Stream, isStream)) {
  import std.traits : ReturnType;
  alias Properties = StreamProperties!Stream;
  alias DG = CollectDelegate!(ReturnType!Fun);
  static struct ForkStreamReceiver(Receiver) {
    // we need to keep track of how many times we have forked
    // then when we are winding down we need to wait until all forks are completed
  }
  static struct ForkStreamOp(Receiver) {
    alias Op = OpType!(Properties.Sender, Receiver);
    DG dg;
    Op op;
    @disable this(ref return scope typeof(this) rhs);
    @disable this(this);
    this(Stream stream, DG dg, Receiver receiver) @trusted {
      this.dg = dg;
      op = stream.collect(cast(Properties.DG)&item).connect(receiver);
    }
    static if (is(Properties.ElementType == void))
      void item() {
        receiver.getScheduler.schedule().then(dg).connectHeap(childReceiver(receiver)).start();
      }
    else
      void item(Properties.ElementType t) {
        just(t).via(receiver.getScheduler.schedule()).then(dg).connectHeap(childReceiver(receiver)).start();
      }
    void start() nothrow @safe {
      op.start();
    }
  }
  return fromStreamOp!(Stream.ElementType, Properties.Value, ForkStreamOp)(stream);
}
+/

/+ the way to do async parsing of http request is as follows

we start with a socket_t

first we need to read the headers
then we need to decide things
then maybe we need to read the content

finally we need to send our response back
as well as any content


reading/parsing of the http request is a Sender operation, it takes the socket_t (possibly a buffer) and returns a HTTPRequest, a socket_t and a buffer with offset

that parsing happens by repeatably starting read operations until we have the http request parsed then completing with that

it sounds a lot like a stream with a takeWhile


at the core we need a buffer that we can grow

so we take a socket_t and a buffer and turn that into a stream

the other option is to use just Senders, how would that look?

defer(&read).then(&updateParser).repeatUntil(&parsed).then(()=>tuple(httprequest,buffer))

so what if asyncRead is abstracted into readOperation, and we first implement it blocking?




struct HTTPParserState {
  ubyte[] buffer;
  auto reqParser = httpRequestParser();
  uint lastPos;
  auto read() {
    return ReadOperation(socket, buffer[lastPos..$]);
  }
  auto updateParser(size_t bytes) {
    auto res = reqParser.parseRequest(buffer[lastPos..bytes], lastPos);
    if (res > 0) {
     // done
    } else {
      if lastPos == buffer.size
        // relocate buffer
      else
        //
    }
  }
  auto finalize() {
  
  }
}

let_with(HTTPParserState(), (state) {
  return defer(&state.read)
    .then(&state.updateParser)
    .repeatUntil(&state.isDone)
    .then(&state.finalize)
});


/// how will it look with a relocatablebuffer?

let_with(HTTPParserState(),(state) => {
  return ReadOperation(state.socket, state.buffer)
    .then(&state.updateParser)
    .repeatUntil(&state.isDone)
    .completeWith(&state.result);
});


/// how with a sequence

let_with(Parser(), (ref parser) => {
  return sequence(
    ReadOperation(socket, buffer),
    parseOperation(&parser, buffer)
  )
  .repeatUntil(&parser.isDone)
  .then(&parser.result)
});





/// how will it look with a stream? better because we don't exhaust the stack
struct {
  socket_t socket;
  Buffer buffer;
  auto reqParser = httpRequestParser();
  int lastPos;
  void start() {
    socketStream(socket, buffer).takeUntil(&this.parseChunk)
  }
  bool parseChunk {
    auto res = reqParser.parseRequest(buffer[lastPos..bytes], lastPos);
    if (res > 0) {
      // done
    } else {
      if lastPos == buffer.size
        // relocate buffer
      else
        //
    }
  }
}


/// how will it look writing the Sender by hand?

struct ParseHTTPHeader {
  socket_t socket;
  RelocatableBuffer buffer;
  static struct Op(Receiver) {
    socket_t socket;
    RelocatableBuffer buffer;
    Receiver receiver;
    void start() {
      readOp = ReadOperation(socket, buffer).connect(ReadReceiver(&this));
      readOp.start();
      
    }
  }
  auto connect(Receiver)(Receiver receiver) {
    ReadOperation(socket, buffer).then()
  }
}




struct ReadOperation {
  socket_t socket;
  ubyte[] buffer;
  static struct ReadOperationOp(Receiver) {
    socket_t socket;
    ubyte[] buffer;
    Receiver receiver;
    auto start() @safe nothrow {
      version (Windows)
        auto len = capToInt(buffer.length);
      else
        auto len = buffer.length;
      if (buffer.length == 0)
        receiver.setValue(0);

      receiver.setValue(.recv(sock, buffer.ptr, len, 0));
    }
  }
  auto connect(Receiver)(return Receiver receiver) @safe scope return {
    auto op = ReadOperationOp!(Receiver)(socket, buffer, receiver);
    return op;
  }
}


+/
