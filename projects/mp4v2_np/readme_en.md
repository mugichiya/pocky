# SEGV on unknown address mp4file.cpp:2662 in MP4File::GetChapters

## Abstract
Segmentation fault (maybe null pointer reference) on libmp4v2.so.2.

## Project Address
[https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3](https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3)


## Build
```
cd /opt
git clone https://github.com/enzo1982/mp4v2.git -b v2.1.3 --depth 1
cd ./mp4v2
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug ../
cmake --build . -j 10
```

To enable Address Sanitizer, add the following options to CMakeFiles.txt.

```
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)
```

## PoC
```
git clone https://github.com/mugichiya/pocky.git
cp -r ./pocky/projects/mp4v2_np/testcases .
./mp4chaps --list ./testcases/0000000000.mp4
```



## ASAN output

```
banjo@ttc:/tmp/mp4v2/build$ ./mp4chaps --list ./testcases/0000000000.mp4
ReadAtom: "./testcases/0000000000.mp4": invalid atom size, extends outside parent atom - skipping to end of "stbl" "stco" 159384830 vs 1298
AddressSanitizer:DEADLYSIGNAL
=================================================================
==3389808==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f74e82f270b bp 0x7fff39dcd780 sp 0x7fff39dcd5b0 T0)
==3389808==The signal is caused by a READ memory access.
==3389808==Hint: address points to the zero page.
    #0 0x7f74e82f270b in mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType) /opt/mp4v2/src/mp4file.cpp:2662
    #1 0x7f74e82c1294 in MP4GetChapters /opt/mp4v2/src/mp4.cpp:1647
    #2 0x5620329500df in mp4v2::util::ChapterUtility::actionList(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:182
    #3 0x562032956476 in mp4v2::util::ChapterUtility::utility_job(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:664
    #4 0x7f74e81db528 in mp4v2::util::Utility::job(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) /opt/mp4v2/libutil/Utility.cpp:298
    #5 0x7f74e81d9626 in mp4v2::util::Utility::batch(int) /opt/mp4v2/libutil/Utility.cpp:105
    #6 0x7f74e81de155 in mp4v2::util::Utility::process_impl() /opt/mp4v2/libutil/Utility.cpp:565
    #7 0x7f74e81dd24e in mp4v2::util::Utility::process() /opt/mp4v2/libutil/Utility.cpp:449
    #8 0x56203295957c in main /opt/mp4v2/util/mp4chaps.cpp:1188
    #9 0x7f74e7823a8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #10 0x7f74e7823b48 in __libc_start_main_impl ../csu/libc-start.c:360
    #11 0x56203294c144 in _start (/opt/mp4v2/build2/mp4chaps+0xf144) (BuildId: 6362905fe8ce5624b29ef2869e210553dee47e65)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /opt/mp4v2/src/mp4file.cpp:2662 in mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType)
==3389808==ABORTING
```

## Solution
It is recommended to insert a null pointer judgment, and take other instruction (if-else/exception handling) if "sample" is NULL.
For example, if branch inserted line 2662 in src/mp4file.cpp can prevent the segfault.

```
                  // we know that sample+2 contains the title (sample[0] and sample[1] is the length)
                    const char * title = (const char *)&(sample[2]);
+                  if (sample == NULL) {
+                                        ...
+                     }
                    int titleLen = min((uint32_t)((sample[0] << 8) | sample[1]), (uint32_t)MP4V2_CHAPTER_TITLE_MAX);
                    strncpy(chapters[i].title, title, titleLen);
                    chapters[i].title[titleLen] = 0;
```
