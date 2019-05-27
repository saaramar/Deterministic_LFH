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

## Uniform Distribution

One important note here, is that we don’t want to pointer to the random data array (ntdll!RtlpLowFragHeapRandomData) to simply overlapped from 0xff to random index between [0x0, 0xff]. Such behavior would mean that the probability we used the values in the beginning of the random data array is much smaller than the probability we used end of the array (the probability we used RtlpLowFragHeapRandomData[0xff] is 1).

So, in order to avoid such a case, the index the code picks from is reset to a random index not at 0xff, but only when the MSB and LSB of the current index are equal (see the branch screenshot above). And it means that we actually have uniform distribution over the entire range [0, 0xff]

For instance, those [traces](https://github.com/saaramar/Deterministic_LFH/raw/master/debug_traces/build_17763_traces.txt) are from build 17763:

```
0:004> bp ntdll!RtlpLowFragHeapAllocFromContext+180 ".printf \"currIDx == 0x%x\\r\\n\", @ax;g"
0:004> g
currIDx == 0x7566
currIDx == 0x7567
currIDx == 0x7568
currIDx == 0x7569
currIDx == 0x756a
currIDx == 0x756b
currIDx == 0x756c
currIDx == 0x756d
currIDx == 0x756e
currIDx == 0x756f
currIDx == 0x7570
currIDx == 0x7571
currIDx == 0x7572
currIDx == 0x7573
currIDx == 0x7574
currIDx == 0x7575 <-- MSB == LSB, call random
currIDx == 0x3233
currIDx == 0x3234
currIDx == 0x3235
currIDx == 0x3236
currIDx == 0x3237
currIDx == 0x3238
currIDx == 0x3239
currIDx == 0x323a
currIDx == 0x323b
currIDx == 0x323c
currIDx == 0x323d
...
currIDx == 0x321e
currIDx == 0x321f
currIDx == 0x3220
currIDx == 0x3221
currIDx == 0x3222
currIDx == 0x3223
currIDx == 0x3224
currIDx == 0x3225
currIDx == 0x3226
currIDx == 0x3227
currIDx == 0x3228
currIDx == 0x3229
currIDx == 0x322a
currIDx == 0x322b
currIDx == 0x322c
currIDx == 0x322d
currIDx == 0x322e
currIDx == 0x322f
currIDx == 0x3230
currIDx == 0x3231
currIDx == 0x3232 <-- MSB == LSB, call random
currIDx == 0x2526
currIDx == 0x2527
currIDx == 0x2528
currIDx == 0x2529
currIDx == 0x252a
...
currIDx == 0x251d
currIDx == 0x251e
currIDx == 0x251f
currIDx == 0x2520
currIDx == 0x2521
currIDx == 0x2522
currIDx == 0x2523
currIDx == 0x2524
currIDx == 0x2525 <-- MSB == LSB, call random
currIDx == 0x5d5e
currIDx == 0x5d5f
currIDx == 0x5d60
currIDx == 0x5d61
```

Take all of those values, and see the distribution:

```
>>> len(dwords_indices_from_RtlpLowFragHeapAllocFromContext)
20370
>>> actual_indices = []
>>> for n in dwords_indices_from_RtlpLowFragHeapAllocFromContext:
...     actual_indices.append(n & 0xff)
...
>>> Counter(actual_indices)
Counter({0: 80, 1: 80, 2: 80, 3: 80, 4: 80, 6: 80, 7: 80, 8: 80, 9: 80, 10: 80, 11: 80, 13: 80, 14: 80, 15: 80, 16: 80, 17: 80, 52: 80, 53: 80, 55: 80, 56: 80, 57: 80, 58: 80, 59: 80, 61: 80, 62: 80, 64: 80, 65: 80, 66: 80, 67: 80, 68: 80, 69: 80, 70: 80, 71: 80, 72: 80, 73: 80, 74: 80, 75: 80, 76: 80, 77: 80, 78: 80, 79: 80, 80: 80, 81: 80, 82: 80, 84: 80, 85: 80, 86: 80, 87: 80, 88: 80, 89: 80, 90: 80, 91: 80, 92: 80, 93: 80, 94: 80, 95: 80, 97: 80, 98: 80, 99: 80, 100: 80, 101: 80, 102: 80, 103: 80, 104: 80, 105: 80, 106: 80, 107: 80, 108: 80, 109: 80, 111: 80, 112: 80, 113: 80, 114: 80, 115: 80, 116: 80, 117: 80, 118: 80, 119: 80, 120: 80, 121: 80, 173: 80, 174: 80, 175: 80, 176: 80, 177: 80, 178: 80, 179: 80, 180: 80, 181: 80, 183: 80, 184: 80, 185: 80, 186: 80, 187: 80, 189: 80, 190: 80, 191: 80, 192: 80, 193: 80, 194: 80, 195: 80, 196: 80, 197: 80, 198: 80, 200: 80, 201: 80, 202: 80, 203: 80, 204: 80, 205: 80, 206: 80, 207: 80, 208: 80, 210: 80, 211: 80, 212: 80, 213: 80, 214: 80, 215: 80, 216: 80, 219: 80, 220: 80, 221: 80, 222: 80, 223: 80, 224: 80, 225: 80, 226: 80, 227: 80, 228: 80, 229: 80, 230: 80, 231: 80, 232: 80, 233: 80, 234: 80, 235: 80, 236: 80, 238: 80, 239: 80, 240: 80, 241: 80, 242: 80, 243: 80, 244: 80, 245: 80, 246: 80, 247: 80, 248: 80, 249: 80, 251: 80, 252: 80, 253: 80, 254: 80, 255: 80, 5: 79, 12: 79, 18: 79, 19: 79, 20: 79, 22: 79, 23: 79, 24: 79, 25: 79, 27: 79, 28: 79, 30: 79, 31: 79, 32: 79, 33: 79, 34: 79, 35: 79, 36: 79, 37: 79, 38: 79, 39: 79, 40: 79, 41: 79, 42: 79, 43: 79, 44: 79, 46: 79, 47: 79, 48: 79, 49: 79, 50: 79, 51: 79, 54: 79, 60: 79, 63: 79, 83: 79, 96: 79, 110: 79, 122: 79, 123: 79, 124: 79, 126: 79, 127: 79, 128: 79, 129: 79, 130: 79, 131: 79, 132: 79, 133: 79, 135: 79, 136: 79, 137: 79, 138: 79, 139: 79, 140: 79, 141: 79, 142: 79, 143: 79, 144: 79, 146: 79, 147: 79, 148: 79, 149: 79, 150: 79, 151: 79, 152: 79, 153: 79, 154: 79, 155: 79, 156: 79, 157: 79, 158: 79, 159: 79, 160: 79, 161: 79, 162: 79, 163: 79, 164: 79, 167: 79, 168: 79, 169: 79, 170: 79, 171: 79, 172: 79, 182: 79, 188: 79, 199: 79, 209: 79, 217: 79, 218: 79, 237: 79, 250: 79, 21: 78, 26: 78, 29: 78, 45: 78, 125: 78, 134: 78, 145: 78, 165: 78, 166: 78})
```