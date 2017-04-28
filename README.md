# deterministic LFH

Windows have done a lot of work on the NT heap internals, replacing the super-old Windows XP lookaside with the LFH (Low Fragmentation Heap, the current front end). I'm not going to talk about the LFH internals, since I assume it's trivial knowledge (we all love to exploit corruptions on the LFH, or in the Page/NonPagePoolNx in the kernel). Also, there are simply *excellent* papers and works describing it in very nice ways. I personally feel I owe a lot to Chris Valasek:

[Understanding the LFH](http://illmatics.com/Understanding_the_LFH.pdf)

[Windows 8 Heap Internals](https://media.blackhat.com/bh-us-12/Briefings/Valasek/BH_US_12_Valasek_Windows_8_Heap_Internals_Slides.pdf)

[Windows 10 Segment Heap](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)

So what do I want to do here? I'm going to present a known issue in the randomization of the LFH in Windows 8+. The randomization, as you all know, came up as mitigation against trivial exploit techniques of UAF or different kinds of corruption vulnerabilities. In those cases, we usually want to shape our heap to get contiguous allocations, or to be able to make the stub malloc() --> free() --> malloc() return the same chunk. So, shaping the heap to be something like that:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/trivial_heap_shape.png "")

is not quite trivial now, since allocations in the LFH are randomized by order. Of-course, a lot of different attacks can be performed (spray the whole userblocks with some desired object, and then corrupt all of them, and a lot more - there is always a way to execute code!), but let's attack the randomization itself here.

The following issue is *NOT* news - it has been known for a long time by now, and I have seen it in many posts and exploits. I just saw a lot of unknown and unware posts and people regarding this, so I thought - why not write trivial POC and a little explanation about it?

New commit: Matt Miller pointed out that this primitive is broken in Windows 10 new build (16179). I was curious, and bindiffed it, reversed the new ntdll and found why. After I present the attack, I'll explain why it no longer holds on build 16179.

## Randomization Implementation

The implementation is really simple. We can find it in the ntdll!RtlpCreateLowFragHeap function (again, I assume you all know the mechanism in ntdll, and you can find a great internals description in the published posts and exploits). There is a call to RtlpInitializeLfhRandomDataArray:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/RtlpInitializeLfhRandomDataArray.png "")

RtlpInitializeLfhRandomDataArray will fill the RtlpLowFragHeapRandomData array with 0x100 random values. This random array will then be used with some other value which together are used to determine some position value. From this position, we look for the first free chunk in the relevant userblocks to return to the user. You can see it all in the initialization of the SubSegment in ntdll!RtlpSubSegmentInitialize. Really simple, right?

## Nice attack

So, trivially, if we'll try to do something like this:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/check_freed.png "")

we'll get different chunks. But, we could do something like this:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/getFreedChunk.png "")

The last malloc will start to search for a free chunk in the bitmap, from the same position it started in the first malloc! So we'll get the same chunk! The *exact* same trick can be used to shape the heap and get contiguous chunks:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/getContiguousAllocations.png "")

chunk1 and chunk2 will be adjcent to each other. Cool!

You can see the trivial POCs in the source. Enjoy.

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/example.png "")

## Windows 10 build 16179

Well, if we just execute my POC on Windows 10 build 16179, we'll see that something breaks.

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/example_16179.png "")

Interesting! Let's see why. I bindiff ntdll, and found pretty quickly that there was no change to the random data array itself (there are no additional writes to RtlpLowFragHeapRandomData), and it remains with the same values for the entire heap lifetime. I actually expected from Microsoft to change that - I mean, you want random? Why not use a *truly* random all the time?

But fine, let's keep looking. Pretty quickly you see that the diff is in the logic of picking a new value from the random data array. The index we are looking for, as I explained before, is just increment by 1 and overlapped on 0x100. Well, in build 16179, this was patched. Now, they add another call to RtlpHeapGenerateRandomValue32(), and with that they change the next index!

code from build 14393:
![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/build_14393_logic.png "")

code from build 16179:
![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/build_16179_logic.png "")

I debugged both of them. You can see the full tracing in the debug_trace directory. I cut one change of the slot and pasted it here.

traces from build 14393:
```
0:001> u RtlpLowFragHeapAllocFromContext+1B1
ntdll!RtlpLowFragHeapAllocFromContext+0x1b1:
00007ffb`13768dd1 470fb68c0860091500 movzx r9d,byte ptr [r8+r9+150960h]
00007ffb`13768dda 418d4001        lea     eax,[r8+1]
00007ffb`13768dde 664123c4        and     ax,r12w
00007ffb`13768de2 668981b2170000  mov     word ptr [rcx+17B2h],ax
00007ffb`13768de9 4d8b4220        mov     r8,qword ptr [r10+20h]
00007ffb`13768ded 4d8b6228        mov     r12,qword ptr [r10+28h]
00007ffb`13768df1 4983f840        cmp     r8,40h
00007ffb`13768df5 0f8250010000    jb      ntdll!RtlpLowFragHeapAllocFromContext+0x32b (00007ffb`13768f4b)
0:001> bp RtlpLowFragHeapAllocFromContext+1B1 ".printf \"RtlpLowFragHeapRandomData == 0x%p, currIdx == 0x%p\\r\\n\", @r9, @r8;g"
0:001> g
...
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000ef
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f0
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f1
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f2
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f3
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f4
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f5
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f6
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f7
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f8
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000f9
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000fa
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000fb
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000fc
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000fd
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000fe
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x00000000000000ff
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000000
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000001
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000002
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000003
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000004
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000005
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000006
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000007
RtlpLowFragHeapRandomData == 0x00007ffb13730000, currIdx == 0x0000000000000008
```

traces from build 16179:
```
0:001> u ntdll!RtlpLowFragHeapAllocFromContext+327
ntdll!RtlpLowFragHeapAllocFromContext+0x327:
00007ffb`e7e5df27 440fb69c0800691500 movzx r11d,byte ptr [rax+rcx+156900h]
00007ffb`e7e5df30 4983f940        cmp     r9,40h
00007ffb`e7e5df34 730e            jae     ntdll!RtlpLowFragHeapAllocFromContext+0x344 (00007ffb`e7e5df44)
00007ffb`e7e5df36 4d8b4628        mov     r8,qword ptr [r14+28h]
00007ffb`e7e5df3a 4c3bce          cmp     r9,rsi
00007ffb`e7e5df3d 7358            jae     ntdll!RtlpLowFragHeapAllocFromContext+0x397 (00007ffb`e7e5df97)
00007ffb`e7e5df3f 418bf1          mov     esi,r9d
00007ffb`e7e5df42 eb53            jmp     ntdll!RtlpLowFragHeapAllocFromContext+0x397 (00007ffb`e7e5df97)
0:001> bp ntdll!RtlpLowFragHeapAllocFromContext+327 ".printf \"RtlpLowFragHeapRandomData == 0x%p, currIdx == 0x%p\\r\\n\", @rcx, @rax;g"
0:001> g
...
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000fc
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000fd
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000fe
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000ff
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x0000000000000000
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000c6	<--- here
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000c7
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000c8
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000c9
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000ca
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000cb
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000cc
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000cd
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000ce
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000cf
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000d0
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000d1
RtlpLowFragHeapRandomData == 0x00007ffbe7e30000, currIdx == 0x00000000000000d2
```