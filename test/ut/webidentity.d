module webidentity;

import s3proxy.webidentity;
import unit_threaded;

@("KeyEncoder")
unittest {
  import std.range : repeat;
  ubyte v = 255;
  v.repeat(5).keyEncoder.should == ['7','7','7','7','7','7','7','7'];
  ubyte[] arr = cast(ubyte[])[0b11111000,0b00111110,0b00001111,0b10000011,0b11100000];
  arr.keyEncoder.should == ['7','A','7','A','7','A','7','A'];
  arr = cast(ubyte[])[0b00000111,0b11000001,0b11110000,0b01111100,0b00011111];
  arr.keyEncoder.should == ['A','7','A','7','A','7','A','7'];
}

@("keyCharToByte")
unittest {
  'A'.keyCharToByte.should == 0;
  'F'.keyCharToByte.should == 5;
  'Z'.keyCharToByte.should == 25;
  '2'.keyCharToByte.should == 26;
  '3'.keyCharToByte.should == 27;
  '4'.keyCharToByte.should == 28;
  '5'.keyCharToByte.should == 29;
  '6'.keyCharToByte.should == 30;
  '7'.keyCharToByte.should == 31;
}

@("KeyDecoder")
unittest {
  import std.string : representation;
  "BIFQYDIOB54HS6T4".representation!(immutable(char)).keyDecoder.should == [10,11,12,13,14,15,120,121,122,124];
}
