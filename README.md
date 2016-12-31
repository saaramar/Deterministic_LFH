# deterministic LFH

Windows have done a lot of work on the NT heap internals, replacing the super-old Windows XP lookaside with the LFH (Low Fragmentation Heap, the current front end). I'm not going to talk about the LFH internals, since I assume it's trivial knowledge (we all love to exploit corruptions on the LFH, or in the Page/NonPagePoolNx in the kernel). Also, there are simply *excellent* papers and works describing it in very nice ways. I personally feel I owe a lot to Chris Valasek:

[Understanding the LFH](http://illmatics.com/Understanding_the_LFH.pdf)

[Windows 8 Heap Internals](https://media.blackhat.com/bh-us-12/Briefings/Valasek/BH_US_12_Valasek_Windows_8_Heap_Internals_Slides.pdf)

[Windows 10 Segment Heap](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)

So what do I want to do here? I'm going to present a known issue in the randomization of the LFH in Windows 8+. The randomization, as you all know, came up as mitigation against trivial exploit techniques of UAF or different kinds of corruption vulnerabilities. In those cases, we usually want to shape our heap to get contiguous allocations, or to be able to make the stub malloc() --> free() --> malloc() return the same chunk. So, shaping the heap to be something like that:

![alt text](https://github.com/saaramar/Deterministic_LFH/raw/master/images/trivial_heap_shape.png "")

is not quite trivial now, since allocations in the LFH are randomized by order. Of-course, a lot of different attacks can be performed (spray the whole userblocks with some desired object, and then corrupt all of them, and a lot more - there is always a way to execute code!), but let's attack the randomization itself here.

The following issue is *NOT* news - it has been known for a long time by now, and I have seen it in many posts and exploits. I just saw a lot of unknown and unware posts and people regarding this, so I thought - why not write trivial POC and a little explanation about it?

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