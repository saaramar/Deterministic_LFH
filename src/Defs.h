#include <Windows.h>

enum STATUS {
	SUCCESS = 0,
	FAIL	= 0xffffffff,
};

#define SIZE 0xc0
#define RandomDataArrayLength 0x100
#define HEAP_ENTRY_SIZE 0x8

void checkRandomization(HANDLE hHeap, size_t size);
STATUS activateLFHBucket(HANDLE hHeap, size_t size);
STATUS getFreedChunk(HANDLE hHeap, size_t size);
STATUS getContiguousAllocations(HANDLE hHeap, size_t size);
