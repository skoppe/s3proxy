module http;

import unit_threaded;
import s3proxy.http;


@("parseQueryParams")
pure @safe unittest {
  import s3proxy.http : parseHttpRequest;
  auto request = parseHttpRequest("GET /test-bucket/resource?delimiter=%2F&prefix=&encoding-type=url&max-keys=100&list-type=2 HTTP/1.1\r\n\r\n");
  request.parseQueryParams().should == ["delimiter":"/", "prefix":"", "encoding-type":"url", "max-keys":"100", "list-type":"2"];

  request = parseHttpRequest("GET /test-bucket/resource? HTTP/1.1\r\n\r\n");
  request.parseQueryParams().should == cast(string[string])null;
}

