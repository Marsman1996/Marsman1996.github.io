#include<windows.h>

//中间件部分
int RtlFreeHeap(_HEAP *Heap, int Flags, void *Mem){
    //free a NULL chunk passed to it
    //如果传递NULL，直接返回
    if(!Mem)
        return;    
    //the header to be used in the freeing process
    //即将在释放过程中用到的头部指针
    _HEAP_ENTRY *Header = NULL;
    _HEAP_ENTRY *HeaderOrig = NULL;
    //you can force the heap to ALWAYS use the back‐end manager
    //可以强制堆总是使用后端管理器
    if(Heap‐>ForceFlags & 0x1000000)
        return RtlpFreeHeap(Heap, Flags | 2, Header, Mem); 
    
    if(Mem & 7)
    {
        RtlpLogHeapFailure(9, Heap, Mem, 0, 0, 0);
        return ERROR;
    }

    //Get the _HEAP_ENTRY header
    //获取_HEAP_ENTRY头
    Header = Mem ‐ 8;
    HeaderOrig = Mem ‐ 8;
    //ben hawkes technique will use this adjustment
    //to point to another chunk of memory
    //Ben Hawkes的技巧会使用这一调整机制来指向到另一个内存chunk
    if(Header‐>UnusedBytes == 0x5)
        Header ‐= 8 * Header‐>SegmentOffset;    
    //another header check to ensure valid frees
    //另一个头部检查来确保合法的释放
    if(!(Header‐>UnusedBytes & 0x3F))
    {
        RtlpLogHeapFailure(8, Heap, Header, 0, 0, 0);
        Header = NULL;
    }
    //if anything went wrong, return ERROR
    //出了问题就返回ERROR
    if(!Header)
        return ERROR; 

    //look at the original header, NOT the adjusted
    //查看原始头，而不是被调整过的
    bool valid_chunk = false;
    if(HeaderOrig‐>UnusedBytes == 0x5)
    {
        //look at adjusted header to determine if in the LFH
        //查看调整过的头来判断是否在LFH中  
        if(Header‐>UnusedBytes & 0x80)
        {
            //RIP Ben Hawkes SegmentOffset attack :(
            //Ben Hawkes SegmentOffset攻击的消亡 :(  
            valid_chunk = RtlpValidateLFHBlock(Heap, Header);
        }
        else
        {
            if(Heap‐>EncodeFlagMask)
            {
                if(!DecodeValidateHeader(Heap, Header))
                    RtlpLogHeapFailure(3, Heap, Header, Mem, 0, 0);    
                else
                    valid_chunk = true;    
            }
        }
        //if it’s found that this is a tainted chunk, return ERROR
        //如果发现chunk被污染了，就返回ERROR  
        if(!valid_chunk)
            return ERROR_BAD_CHUNK;    
    }

    //and ensure that all the meta‐data is correct
    //确保所有的元数据都是正确的
    Header = DecodeValidateHeader(Heap, Header);
    //being bitwase ANDed with 0x80 denotes a chunk from the LFH
    //与0x80按位与，指示chunk是否来自LFH
    if(Header‐>UnusedBytes & 0x80)
        return RtlpLowFragHeapFree(Heap, Header);    
    else
        return RtlpFreeHeap(Heap, Flags | 2, Header, Mem); 
}

//后端
int RtlpFreeHeap(_HEAP *Heap, int Flags, _HEAP_ENTRY *Header, void *Chunk){
    if(Heap == Header)
    {
        RtlpLogHeapFailure(9, Heap, Header, 0,0,0);    
        return;    
    }
    //attempt to decode and validate the header
    //if it doesn't decode properly, abort
    //试图解码并校验头部，如果解码有问题就中止
    if(Heap‐>EncodeFlagMask)
        if(!DecodeValidateHeader(Header, Heap))    
            return;

    //search for the appropriately sized blocksindex
    //搜索合适尺寸的BlocksIndex
    _HEAP_LIST_LOOKUP *BlocksIndex = Heap‐>BlocksIndex;
    do
    {
        if(Header‐>Size < BlocksIndex‐>ArraySize)
           break;  
        BlocksIndex = BlocksIndex‐>ExtendedLookup;
    }
    while(BlocksIndex);
    //the UnusedBytes (offset: 0x7) are used for many things
    //a value of 0x4 indicates that the chunk was virtually
    //allocated and needs to be freed that way (safe linking included)
    //UnusedBytes(offset:0x7)用处广泛，0x4值指示了该chunk是虚分配的，需要通过
    //同样的方式来释放(也包含安全链入)
    if(Header‐>UnusedBytes == 0x4)
        return VirtualFree(Head, Header);

    //maximum permitted for the LFH
    //LFH最大的允许值
    int Size = Header‐>Size;
    //if the chunk is capable of being serviced by the LFH then check the
    //counters, if they are greater than 1 decrement the value to denote
    //that an item has been freed, remember, you need at least 16 CONSECUTIVE
    //allocations to enable the LFH for a given size
    //如果LFH有能力为该chunk服务，就检查计数器，如果大于1就递减该值来表示该条目已经被释放了
    //记住，你需要至少16个连续分配才能为特定尺寸激活LFH
    if(Size < Heap‐>FrontEndHeapMaximumIndex)
    {
        if(!( (1 << Size & 7) & (heap‐>FrontEndStatusBitmap[Size / 8])))
        {
            if(Heap‐>FrontEndHeapUsageData[Size] > 1)
            Heap‐>FrontEndHeapUsageData[Size]‐‐;
        }
    }

    //if we can coalesce the chunks adjacent to this one, do it to
    //avoid fragmentation (something the LFH directly addresses)
    //如果我们可以合并chunks，就合并，避免碎片化
    int CoalescedSize;
    if(!(heap‐>Flags 0x80))
    {
        Header = RtlpCoalesceFreeBlocks(Heap, Header, &CoalescedSize, 0);
     
        //if the combined space is greater than the Heap‐>DecommittThreshold
        //then decommit the chunk from memory
       //如果合并的空间大于Heap‐>DecommittThreshold，就decommit该chunk内存  
        DetermineDecommitStatus(Heap, Header, CoalescedSize);
     
        //if the chunk is greater than the VirtualMemoryThreshold
        //insert it and update the appropriate lists
       //如果chunk大于VirtualMemoryThreshold，插入并更新对应的链表  
        if(CoalescedSize > 0xFE00)
         RtlpInsertFreeBlock(Heap, Header, CoalescedSize);    
    }

    //get a pointer to the FreeList head
    //获取指向FreeList头的指针
    _LIST_ENTRY *InsertPoint = &Heap‐>FreeLists;
    _LIST_ENTRY *NewNode;
    //get the blocks index and attempt to assign
    //the index at which to free the current chunk
    //获取blocks索引，尝试赋予该索引释放当前chunk的位置
    _HEAP_LIST_LOOKUP *BlocksIndex = Heap‐>BlocksIndex;
    int ListHintIndex;
    Header‐>Flags = 0;
    Header‐>UnusedBytes = 0;
    //attempt to find the proper insertion point to insert
    //chunk being freed, which will happen at the when a freelist
    //entry that is greater than or equal to CoalescedSize is located
    //尝试找到合适的插入点，插入chunk
    if(Heap‐>BlocksIndex)
        InsertPoint = RtlpFindEntry(Heap, CoalescedSize);    
    else
        InsertPoint = *InsertPoint;    
    //find the insertion point within the freelists
    while(&heap‐>FreeLists != InsertPoint)
    {
        _HEAP_ENTRY *CurrEntry = InsertPoint ‐ 8;
        if(heap‐>EncodeFlagMask)
         DecodeHeader(CurrEntry, Heap);    
        if(CoalescedSize <= CurrEntry‐>Size)
         break;    
        InsertPoint = InsertPoint‐>Flink;
    }

    //insertion attacks FOILED! Hi Brett Moore/Nico
    NewNode = Header + 8;
    _LIST_ENTRY *Blink = InsertPoint‐>Blink;
    if(Blink‐>Flink == InsertPoint)
    {
        NewNode‐>Flink = InsertPoint;
        NewNode‐>Blink = Blink;
        Blink‐>Flink = NewNode;
        Blink = NewNode;
    }
    else
    {
        RtlpLogHeapFailure(12, 0, InsertPoint, 0, Blink‐>Flink, 0);    
    }

    //update the total free blocks available to this heap
    Heap‐>TotalFreeSize += Header‐>Size;
    //if we have a valid _HEAP_LIST_LOOKUP structure, find
    //the appropriate index to use to update the ListHints
    if(BlocksIndex)
    {
        int Size = Header‐>Size;
        int ListHintIndex;
        while(Size >= BlocksIndex‐>ArraySize)
        {
            if(!BlocksIndex‐>ExtendedLookup)
            {
                ListHintIndex = BlocksIndex‐>ArraySize ‐ 1;
                break;
            }
            BlocksIndex = BlocksIndex‐>ExtendedLookup;
        }
        //add the current entry to the ListHints doubly linked list
        RtlpHeapAddListEntry(Heap, BlocksIndex, RtlpHeapFreeListCompare,
        NewNode, ListHintIndex, Size);
    }
}

//前端
int RtlpLowFragHeapFree(_HEAP *Heap, _HEAP_ENTRY *Header){
    //derive the subsegment from the chunk to be freed, this
    //can royally screw up an exploit for a sequential overflow
    _HEAP_SUBSEGMENT *Subseg = (DWORD)Heap ^ RtlpLFHKey ^ *(DWORD)Header ^ (Header >> 3);
    _HEAP_USERDATA_HEADER *UserBlocks = Subseg‐>UserBlocks;
    //Get the AggrExchg which contains the Depth (how many left)
    //and the Hint (at what offset) [not really used anymore]
    _INTERLOCK_SEQ *AggrExchg = AtomicAcquireIntSeq(Subseg);

    //the PreviousSize is now used to hold the index into the UserBlock
    //for each chunk. this is somewhat like the FreeEntryOffset used before it
    //See RtlpSubSegmentInitialize() for details on how this is initialized
    short BitmapIndex = Header‐>PreviousSize;
    //Set the chunk as free
    Header‐>UnusedBytes = 0x80;
    //zero out the bitmap based on the predefined index set in RtlpSubSegmentInitialize
    //via the BTR (Bit‐test and Reset) x86 instruction
    bittestandreset(UserBlocks‐>BusyBitmap‐>Buffer, BitmapIndex);

    //If there are any of these chunks, attempt to free them
    //by resetting the bitmap
    int DelayedFreeCount;
    if(Subseg‐>DelayFreeList‐>Depth)
        FreeDelayedChunks(Subseg, &DelayedFreeCount);    
    //now it’s time to update the Depth and Hint for the current Subsegment
    //1) The Depth will be increased by 1, since we're adding an item back into the UserBlock
    //2) The Hint will be set to the index of the chunk being freed
    _INTERLOCK_SEQ NewSeq;
    int NewDepth = AggrExchg‐>Depth + 1 + DelayedFreeCount;
    NewSeq.Depth = NewDepth;
    NewSeq.Hint = BitmapIndex;
    //if the UserBlocks still have BUSY chunks in it then update
    //the AggregateExchg and return back to the calling function
    if(!EmptyUserBlock(Subseg))
    {
        Subseg‐>AggregateExchang = NewSeq;
        return NewSeq;
    }

    //Update the list if we've freed any chunks
    //that were previously in the delayed state
    UpdateDelayedFreeList(Subseg);
    //update the CachedItem[] array with the _HEAP_SUBSEGMENT
    //we're about to free below
    UpdateCache(Subseg‐>LocalInfo);
    Subseg‐>AggregateExchang.Depth = 0;
    Subseg‐>AggregateExchang.Hint = 0;
    int ret = InterlockedExchange(&Subseg‐>ActiveSubsegment, 0);
    if(ret)
        UpdateLockingMechanisms(Subseg)
    
    //if certain flags are set this will mark prtection for the next page in the userblock
    if(Subseg‐>Flags & 3 != 0)
    {
        //get a page aligned address
        void *PageAligned = (Subseg‐>UserBlock + 0x101F) & 0xFFFFF000;
    
        int UserBlockByteSize = Subseg‐>BlockCount * RtlpGetReservedBlockSize(Subseg);
        UserBlockByteSize *= 8;
    
        //depending on the flags, make the memory read/write or rwx
        //http://msdn.microsoft.com/en‐us/library/windows/desktop/aa366786(v=vs.85).aspx
        DWORD Protect = PAGE_READWRITE;
        if(flags & 40000 != 0)
            Protect = PAGE_EXECUTE_READWRITE;    
        //insert a non‐executable memory page
        DWORD output;
        ZwProtectVirtualMemory(‐1, &PageAligned, &UserBlockByteSize, Protect, &output);
    }

    //Free all the chunks (not individually) by freeing the UserBlocks structure
    Subseg‐>UserBlocks‐>Signature = 0;
    RtlpFreeUserBlock(Subseg‐>LocalInfo‐>LocalData‐>LowFragHeap, Subseg‐>UserBlocks);
    return;
}