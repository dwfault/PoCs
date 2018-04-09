## libwebm Vp9HeaderParser UAF by PrintVP9Info

### Overview

A Use-After-Free bug exists in function `OutputCluster` in webm_info.cc of webmproject/libwebm below git version 12b42e9. The bug exists because of the combination of  process logic in `Vp9HeaderParser::SetFrame` and misuse of it.

The ASAN log are as follows:

```
./webm_info -all -i ../id00010-uaf.webm 
EBML Header:
  EBMLVersion       : 1
  EBMLReadVersion   : 1
  EBMLMaxIDLength   : 4
  EBMLMaxSizeLength : 8
  Doc Type          : webm
  DocTypeVersion    : 4
  DocTypeReadVersion: 2
Segment:  @: 43  size: 11549
  SegmentInfo:  @: 278  size: 67
    TimecodeScale : 1000000 
    Duration(secs): 2.08
    MuxingApp     : Google
    WritingApp    : Google
  Tracks:  @: 345  size: 84
    Track:  @: 357  size: 72
      TrackType   : 1
      TrackNumber : 1
      CodecID     : V_VP9
      DefaultDuration: 80000000
      PixelWidth  : 256
      PixelHeight : 144
      DisplayWidth  : 128
      DisplayHeight : 144
      DisplayUnit   : 0
  Clusters (count):1
  Cluster:  @: 429  size: 11123
    Timecode (sec) : 0
    Duration (sec) : 2
    # Blocks       : 26
    Block: type:V frame:I secs:    0 @_payload: 446 size_payload: 45 key:1 v:0 altref:0 errm:0 ct:1 fpm:0 cs:0
    Block: type:V frame:I secs: 0.08 @_payload: 493 size_payload: 44 key:1 v:0 altref:0 errm:0 ct:1 fpm:0 cs:0
=================================================================
==48021==ERROR: AddressSanitizer: heap-use-after-free on address 0x61900000558f at pc 0x000000420c5d bp 0x7ffea1c25d60 sp 0x7ffea1c25d50
READ of size 1 at 0x61900000558f thread T0
    #0 0x420c5c in vp9_parser::Vp9HeaderParser::ReadBit() /home/default/Desktop/libwebm-master-asan/common/vp9_header_parser.cc:119
    #1 0x420c5c in vp9_parser::Vp9HeaderParser::VpxReadLiteral(int) /home/default/Desktop/libwebm-master-asan/common/vp9_header_parser.cc:130
    #2 0x420c5c in vp9_parser::Vp9HeaderParser::ParseUncompressedHeader() /home/default/Desktop/libwebm-master-asan/common/vp9_header_parser.cc:37
    #3 0x43b684 in PrintVP9Info /home/default/Desktop/libwebm-master-asan/webm_info.cc:719
    #4 0x43b684 in OutputCluster /home/default/Desktop/libwebm-master-asan/webm_info.cc:1027
    #5 0x413818 in main /home/default/Desktop/libwebm-master-asan/webm_info.cc:1273
    #6 0x7f578f3d182f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #7 0x417d98 in _start (/home/default/Desktop/libwebm-master-asan/webm_info+0x417d98)

0x61900000558f is located 15 bytes inside of 1065-byte region [0x619000005580,0x6190000059a9)
freed by thread T0 here:
    #0 0x7f578fdacb2a in operator delete(void*) (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x99b2a)
    #1 0x440fbf in __gnu_cxx::new_allocator<unsigned char>::deallocate(unsigned char*, unsigned long) /usr/include/c++/5/ext/new_allocator.h:110
    #2 0x440fbf in std::allocator_traits<std::allocator<unsigned char> >::deallocate(std::allocator<unsigned char>&, unsigned char*, unsigned long) /usr/include/c++/5/bits/alloc_traits.h:517
    #3 0x440fbf in std::_Vector_base<unsigned char, std::allocator<unsigned char> >::_M_deallocate(unsigned char*, unsigned long) /usr/include/c++/5/bits/stl_vector.h:178
    #4 0x440fbf in std::vector<unsigned char, std::allocator<unsigned char> >::_M_default_append(unsigned long) /usr/include/c++/5/bits/vector.tcc:578

previously allocated by thread T0 here:
    #0 0x7f578fdac532 in operator new(unsigned long) (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x99532)
    #1 0x440ed7 in __gnu_cxx::new_allocator<unsigned char>::allocate(unsigned long, void const*) /usr/include/c++/5/ext/new_allocator.h:104
    #2 0x440ed7 in std::allocator_traits<std::allocator<unsigned char> >::allocate(std::allocator<unsigned char>&, unsigned long) /usr/include/c++/5/bits/alloc_traits.h:491
    #3 0x440ed7 in std::_Vector_base<unsigned char, std::allocator<unsigned char> >::_M_allocate(unsigned long) /usr/include/c++/5/bits/stl_vector.h:170
    #4 0x440ed7 in std::vector<unsigned char, std::allocator<unsigned char> >::_M_default_append(unsigned long) /usr/include/c++/5/bits/vector.tcc:557

SUMMARY: AddressSanitizer: heap-use-after-free /home/default/Desktop/libwebm-master-asan/common/vp9_header_parser.cc:119 vp9_parser::Vp9HeaderParser::ReadBit()
Shadow bytes around the buggy address:
  0x0c327fff8a60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8a70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8a80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8a90: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff8aa0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
=>0x0c327fff8ab0: fd[fd]fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c327fff8ac0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c327fff8ad0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c327fff8ae0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c327fff8af0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
  0x0c327fff8b00: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
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
==48021==ABORTING
```



### Root cause

In function `OutputCluster`, the argument `vp9_parser::Vp9HeaderParser* parser` was initialized by `vp9parser::Vp9HeaderParser::SetFrame` in  `PrintVP9Info`:

```c++
void PrintVP9Info(const uint8_t* data, int size, FILE* o, int64_t time_ns,
                  FrameStats* stats, vp9_parser::Vp9HeaderParser* parser,
                  vp9_parser::Vp9LevelStats* level_stats) {
  if (size < 1)
    return;

  uint32_t sizes[8];
  int i = 0, count = 0;
  ParseSuperframeIndex(data, size, sizes, &count);

  // Remove all frames that are less than window size.
  while (!stats->window.empty() &&
         stats->window.front() < (time_ns - (kNanosecondsPerSecondi - 1)))
    stats->window.pop();

  do {
    const size_t frame_length = (count > 0) ? sizes[i] : size;
    if (frame_length > std::numeric_limits<int>::max() ||
        static_cast<int>(frame_length) > size) {
      fprintf(o, " invalid VP9 frame size (%u)\n",
              static_cast<uint32_t>(frame_length));
      return;
    }
    parser->SetFrame(data, frame_length);
    if (!parser->ParseUncompressedHeader())
      return;
    ...
```

```c++
bool Vp9HeaderParser::SetFrame(const uint8_t* frame, size_t length) {
  if (!frame || length == 0)
    return false;

  frame_ = frame;
  frame_size_ = length;
  bit_offset_ = 0;
  profile_ = -1;
  show_existing_frame_ = 0;
  key_ = 0;
  altref_ = 0;
  error_resilient_mode_ = 0;
  intra_only_ = 0;
  reset_frame_context_ = 0;
  color_space_ = 0;
  color_range_ = 0;
  subsampling_x_ = 0;
  subsampling_y_ = 0;
  refresh_frame_flags_ = 0;
  return true;
}
```

If `parser` was initialized once before, its property  `frame_` would not be changed because of 

`if (!frame || length == 0)return false;`, then  `frame_` was used in `Vp9HeaderParser::ReadBit` called by `Vp9HeaderParser::VpxReadLiteral` and by `Vp9HeaderParser::ParseUncompressedHeader`.



The initialization of `parser` happens in `Vp9HeaderParser::SetFrame`, of which the argument `data` was passed from `vector_data` in `OutputCluster`. While in function OutputCluster, the `vector_data` as a `std::vector<unsigned char>`, is always able to be reallocated in code:

```c++
vector_data.resize(frame.len + 1024);
```

But the`frame_` of  `parser` was never reinitialized. That leads to a Use-After-Free situation. 



### Fix suggestion

`Vp9HeaderParser::SetFrame` should be reconsidered to be reinitialized-supported.

