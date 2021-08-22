module chunk;

import unit_threaded;
import s3proxy.chunk;

ubyte[] toUbyte(string s) @trusted pure {
  return cast(ubyte[])s;
}

@("readChunkIntoBuffer")
pure @safe unittest {
  ubyte[12] buffer;
  ubyte[] localBuffer = buffer;
  ubyte[] data = "5;chunk-signature=2431bbda17e21721a6f6d3afb0a4e7c41581cc63a6d45c61556700a807c26f03\r\n12345\r\n0;chunk-signature=a4794a7b42eb87eda5269d68d7eedac0791cc3d7ec01bf87236f6faef4b20f7a\r\n\r\n".toUbyte();
  auto chunk = data.readChunkIntoBuffer(localBuffer);

  (&buffer[0]).shouldNotEqual(&localBuffer[0]);
  chunk.extension.should == ";chunk-signature=2431bbda17e21721a6f6d3afb0a4e7c41581cc63a6d45c61556700a807c26f03";
  chunk.data.length.should == 5;
  chunk.data.should == cast(ubyte[])[49, 50, 51, 52, 53];

  chunk = data.readChunkIntoBuffer(localBuffer);
  chunk.extension.should == ";chunk-signature=a4794a7b42eb87eda5269d68d7eedac0791cc3d7ec01bf87236f6faef4b20f7a";
  chunk.data.length.should == 0;
}

@("readChunkIntoBuffer")
pure @safe unittest {
  ubyte[256] buffer;
  ubyte[] localBuffer = buffer;
  ubyte[][] data = ["5;chunk-signature=2431bbda17e21721a6f6d3afb0a4e7c41581cc63a6d45c61556700a807c26f03\r\n12345\r\n".toUbyte,"0;chunk-signature=a4794a7b42eb87eda5269d68d7eedac0791cc3d7ec01bf87236f6faef4b20f7a\r\n\r\n".toUbyte];
  import std.algorithm : joiner;
  auto range = data.joiner();
  auto chunk = range.readChunkIntoBuffer(localBuffer);

  (&buffer[0]).should == &localBuffer[0];
  chunk.extension.should == ";chunk-signature=2431bbda17e21721a6f6d3afb0a4e7c41581cc63a6d45c61556700a807c26f03";
  chunk.data.length.should == 5;
  chunk.data.should == cast(ubyte[])[49, 50, 51, 52, 53];

  chunk = range.readChunkIntoBuffer(localBuffer);

  (&buffer[0]).should == &localBuffer[0];
  chunk.extension.should == ";chunk-signature=a4794a7b42eb87eda5269d68d7eedac0791cc3d7ec01bf87236f6faef4b20f7a";
  chunk.data.length.should == 0;
}

@("rebuffer")
unittest {
  import aws.aws;
  import std.algorithm : joiner, map;
  import std.array : array;
  ubyte[][] data = [['h','e','l','l'],['o',' ','b','r'],['a','v','e',' '],['n','e','w',' '],['w','o','r','l'],['d']];
  ubyte[] buffer = new ubyte[12];
  data.rebuffer(buffer).map!(c => c.dup).array.should == [['h','e','l','l','o',' ','b','r','a','v','e',' '],['n','e','w',' ','w','o','r','l','d']];
}
