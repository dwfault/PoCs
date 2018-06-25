## libwebm ParseVP9SuperFrameIndex OOB read

credit by ADLab of Venustech.

### Overview

A bug exists in function `ParseVP9SuperFrameIndex` in libwebm_utils.cc of webmproject/libwebm below git version 12b42e9. The bug exists because of lack of value check. And it could result in a info leak vulnerability.

The ASAN log are as follows:

```
/webm2pes ../id00013-ff.webm ../id00013-ff.pes
==33755==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60700000dd58 at pc 0x0000004265ec bp 0x7ffc4ee44db0 sp 0x7ffc4ee44da0
READ of size 1 at 0x60700000dd58 thread T0
    #0 0x4265eb in libwebm::CopyAndEscapeStartCodes(unsigned char const*, unsigned long, std::vector<unsigned char, std::allocator<unsigned char> >*) /home/default/Desktop/libwebm-master-asan/m2ts/webm2pes.cc:514
    #1 0x4265eb in libwebm::Webm2Pes::WritePesPacket(libwebm::VideoFrame const&, std::vector<unsigned char, std::allocator<unsigned char> >*) /home/default/Desktop/libwebm-master-asan/m2ts/webm2pes.cc:473
    #2 0x4273a0 in libwebm::Webm2Pes::ConvertToFile() /home/default/Desktop/libwebm-master-asan/m2ts/webm2pes.cc:253
    #3 0x40b4f1 in main /home/default/Desktop/libwebm-master-asan/m2ts/webm2pes_main.cc:32
    #4 0x7f315558c82f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #5 0x40be78 in _start (/home/default/Desktop/libwebm-master-asan/webm2pes+0x40be78)

0x60700000dd58 is located 0 bytes to the right of 72-byte region [0x60700000dd10,0x60700000dd58)
allocated by thread T0 here:
    #0 0x7f3155f676b2 in operator new[](unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x996b2)
    #1 0x40ea7d in libwebm::VideoFrame::Buffer::Init(unsigned long) /home/default/Desktop/libwebm-master-asan/common/video_frame.cc:15
    #2 0x40ea7d in libwebm::VideoFrame::Init(unsigned long) /home/default/Desktop/libwebm-master-asan/common/video_frame.cc:27

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/default/Desktop/libwebm-master-asan/m2ts/webm2pes.cc:514 libwebm::CopyAndEscapeStartCodes(unsigned char const*, unsigned long, std::vector<unsigned char, std::allocator<unsigned char> >*)
Shadow bytes around the buggy address:
  0x0c0e7fff9b50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff9b60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff9b70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff9b80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c0e7fff9b90: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c0e7fff9ba0: fa fa 00 00 00 00 00 00 00 00 00[fa]fa fa fa fa
  0x0c0e7fff9bb0: 00 00 00 00 00 00 00 00 00 00 fa fa fa fa 00 00
  0x0c0e7fff9bc0: 00 00 00 00 00 00 00 00 fa fa fa fa 00 00 00 00
  0x0c0e7fff9bd0: 00 00 00 00 00 fa fa fa fa fa 00 00 00 00 00 00
  0x0c0e7fff9be0: 00 00 00 fa fa fa fa fa 00 00 00 00 00 00 00 00
  0x0c0e7fff9bf0: 00 00 fa fa fa fa 00 00 00 00 00 00 00 00 00 fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
==33755==ABORTING
```



### Root cause

The root cause of the bug is that function `ParseVP9SuperFrameIndex` lacks of a proper value check. And the unchecked value was used as a length in following logic of code.

```
bool ParseVP9SuperFrameIndex(const std::uint8_t* frame,
                             std::size_t frame_length, Ranges* frame_ranges) {
  if (frame == nullptr || frame_length == 0 || frame_ranges == nullptr)
    return false;

  bool parse_ok = false;
  const std::uint8_t marker = frame[frame_length - 1];
  const std::uint32_t kHasSuperFrameIndexMask = 0xe0;
  const std::uint32_t kSuperFrameMarker = 0xc0;
  const std::uint32_t kLengthFieldSizeMask = 0x3;

  if ((marker & kHasSuperFrameIndexMask) == kSuperFrameMarker) {
    const std::uint32_t kFrameCountMask = 0x7;
    const int num_frames = (marker & kFrameCountMask) + 1;
    const int length_field_size = ((marker >> 3) & kLengthFieldSizeMask) + 1;
    const std::size_t index_length = 2 + length_field_size * num_frames;

    if (frame_length < index_length) {
      std::fprintf(stderr, "VP9Parse: Invalid superframe index size.\n");
      return false;
    }

    // Consume the super frame index. Note: it's at the end of the super frame.
    const std::size_t length = frame_length - index_length;

    if (length >= index_length &&
        frame[frame_length - index_length] == marker) {
      // Found a valid superframe index.
      const std::uint8_t* byte = frame + length + 1;

      std::size_t frame_offset = 0;
      for (int i = 0; i < num_frames; ++i) {
        std::uint32_t child_frame_length = 0;

        for (int j = 0; j < length_field_size; ++j) {
          child_frame_length |= (*byte++) << (j * 8);
        }

        frame_ranges->push_back(Range(frame_offset, child_frame_length));
        frame_offset += child_frame_length;
      }

      if (static_cast<int>(frame_ranges->size()) != num_frames) {
        std::fprintf(stderr, "VP9Parse: superframe index parse failed.\n");
        return false;
      }

      parse_ok = true;
    } else {
      std::fprintf(stderr, "VP9Parse: Invalid superframe index.\n");
    }
  }
  return parse_ok;
}
```

The `child_frame_length` comes directly from .webm file raw data:

```
xxd -g 1  ../id00013-ff.webm:
00000000: 1a 45 df a3 9f 42 86 81 01 42 f7 81 01 42 f2 81  .E...B...B...B..
00000010: 04 42 f3 81 08 42 82 84 77 65 62 6d 42 87 81 02  .B...B..webmB...
00000020: 42 85 81 02 18 53 80 67 01 00 00 00 00 00 0f 7f  B....S.g........
00000030: 11 4d 9b 74 b9 4d bb 8b 53 ab 84 15 49 a9 66 53  .M.t.M..S...I.fS
...
000001a0: 20 86 00 40 96 9c 00 41 60 00 03 20 00 00 55 30   ..@...A`.. ..U0
000001b0: 20 c1 [ff] 10 c1 a3 94 81 00 42 00 86 00 40 96 9c   ........B...@..
...
```



In the situation when `ParseVP9SuperFrameIndex` was called by webm2pes or webm2ts, there would be file transform operations. While the code pre-allocated only 0x50 bytes space for function `CopyAndEscapeStartCodes`, in which 0xff bytes was read from a 0x50 bytes chunk, and copy to the .pes file. It means an out-of-bound write, and could write extra heap metadata to the output file:

```
gdb-peda$ x/255b 0x65c6b0
0x65c6b0:       0x84    0x00    0x80    0x49    0x4e    0x80    0x20    0x00
0x65c6b8:       0x00    0x01    0x00    0x00    0x00    0x55    0x30    0x20
0x65c6c0:       0x86    0x00    0x40    0x96    0x9c    0x00    0x41    0x60
0x65c6c8:       0x00    0x03    0x20    0x00    0x00    0x55    0x30    0x20
0x65c6d0:       0xc1    0xff    0x10    0xc1    0x00    0x00    0x00    0x00
0x65c6d8:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c6e0:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c6e8:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c6f0:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c6f8:       0x21    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c700:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c708:       0xff    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c710:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c718:       0x31    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c720:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c728:       0xff    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c730:       0xff    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c738:       0x10    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c740:       0x20    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c748:       0x51    0x01    0x00    0x00    0x00    0x00    0x00    0x00
0x65c750:       [0x78    0x9b    0x83    0xf7    0xff    0x7f    0x00    0x00]
0x65c758:       [0x78    0x9b    0x83    0xf7    0xff    0x7f    0x00    0x00]
0x65c760:       0x40    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c768:       0x20    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c770:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c778:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c780:       0x60    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c788:       0x30    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c790:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x65c798:       0x06    0x21    0x00    0x01    0x00    0x01    0xff    0x42
0x65c7a0:       0x43    0x4d    0x56    0x00    0x00    0x00    0x86    0x00
0x65c7a8:       0x00    0x82    0x49    0x83    0x42    0x20    0x04

gdb-peda$ parseheap
addr                prev      size      status            fd                bk
0x643000            0x0       0x11c10    Used                None              None
0x654c10            0x0       0x20       Used                None              None
0x654c30            0x6d62    0x20       Used                None              None
0x654c50            0x73      0x20       Used                None              None
0x654c70            0x6d62    0x20       Used                None              None
0x654c90            0x73      0x230      Used                None              None
0x654ec0            0x7ffff78382600x230      Used                None              None
0x6550f0            0x7ffff78382600x1010     Used                None              None
0x656100            0x0       0xd0       Used                None              None
0x6561d0            0x800     0x50       Used                None              None
0x656220            0x0       0x90       Used                None              None
0x6562b0            0x0       0x60       Used                None              None
0x656310            0x0       0x20       Used                None              None
0x656330            0x0       0x20       Used                None              None
0x656350            0x0       0x40       Used                None              None
0x656390            0x6563a8  0x20       Used                None              None
0x6563b0            0x0       0x20       Used                None              None
0x6563d0            0x20      0x110      Used                None              None
0x6564e0            0x0       0x20       Used                None              None
0x656500            0x0       0x50       Used                None              None
0x656550            0x2       0x4010     Used                None              None
0x65a560            0x0       0x50       Used                None              None
0x65a5b0            0xfa2     0x2010     Used                None              None
0x65c5c0            0x0       0x60       Used                None              None
0x65c620            0x0       0x60       Used                None              None
0x65c680            0xec3fb4f677312d8e0x20       Used                None              None
0x65c6a0            0xc62928e9444ed760[0x50]       Used                None              None
0x65c6f0            0x0       0x20       [Freed]                0x0              None
0x65c710            0x0       0x30       Used                None              None
0x65c740            0x20      0x150      Freed     [0x7ffff7839b78    0x7ffff7839b78]
0x65c890            0x150     0x110      Used                None              None
0x65c9a0            0x0       0x1010     Used                None              None

xxd -g 1  ../id00013-ff.pes 
00000000: 00 00 01 e0 00 8f 80 80 06 21 00 01 00 01 ff 42  .........!.....B
00000010: 43 4d 56 00 00 00 86 00 00 82 49 83 42 20 04 f0  CMV.......I.B ..
00000020: 07 f6 00 38 24 1c 18 00 00 00 c0 7f 37 d1 ff 1d  ...8$.......7...
00000030: 90 47 40 b8 0c 00 00 7c ce 2c 73 29 7e e5 87 d7  .G@....|.,s)~...
00000040: a6 b5 7f 1c 22 4d 6b ef c3 ed 49 3a 3f 66 31 36  ...."Mk...I:?f16
00000050: 3d d1 7b 24 51 9b 46 e3 eb 2c 6f f6 fa 9a 54 c0  =.{$Q.F..,o...T.
00000060: b4 f5 20 a8 6f cc 10 44 72 8e 2d 31 77 f6 b4 3f  .. .o..Dr.-1w..?
00000070: ec 93 19 e2 6a 3d 67 9a 1b 77 91 fa d2 65 a4 ee  ....j=g..w...e..
00000080: 21 d0 90 ae 96 9d a1 15 66 60 d7 4e 44 e9 28 29  !.......f`.ND.()
00000090: c6 f6 a8 d0 00 00 00 01 e0 01 12 80 80 06 21 00  ..............!.
000000a0: 01 17 35 ff 42 43 4d 56 00 00 03 01 09 00 00 84  ..5.BCMV........
000000b0: 00 80 49 4e 80 20 00 00 03 01 00 00 00 55 30 20  ..IN. .......U0 
000000c0: 86 00 40 96 9c 00 41 60 00 03 20 00 00 55 30 20  ..@...A`.. ..U0 
000000d0: c1 ff 10 c1 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000000f0: 00 00 00 00 00 00 00 00 21 00 00 00 00 00 00 00  ........!.......
00000100: 00 00 00 00 00 00 00 00 ff 00 00 00 00 00 00 00  ................
00000110: 00 00 00 00 00 00 00 00 31 00 00 00 00 00 00 00  ........1.......
00000120: 00 00 00 00 00 00 00 00 ff 00 00 00 00 00 00 00  ................
00000130: ff 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00  ................
00000140: 20 00 00 00 00 00 00 00 51 01 00 00 00 00 00 00   .......Q.......
00000150: [78 9b 83 f7 ff 7f 00 00 78 9b 83 f7 ff 7f 00 00]  x.......x.......
00000160: 40 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00  @....... .......
...
```

As it shows, the `0x7ffff7839b78` resides in a free chunk `0x65c740 `, and indicates `fd`, `bk` of it. Those bytes was written into the output .pes file in the webm2pes, webm2ts situations and cause a simple info leak. While in other execution contexts such as browsers, there could exist potential unknown exploitation method.

