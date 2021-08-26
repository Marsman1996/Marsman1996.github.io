#include<windows.h>

//中间件
void *RtlAllocateHeap(_HEAP *Heap, DWORD Flags, size_t Size){
    void *chunk;
    //if the size is above 2GB, it won't be serviced
    //如果尺寸大于2GB，是不会服务该请求的
    if(Size > 0x7FFFFFFF)
        return ERROR_TOO_BIG;
    //ensure that at least 1‐byte will be allocated
    //and subsequently rounded (result ==> 8 byte alloc)
    //确保至少分配一个字节，向上取整就是8个字节
    if(Size == 0)
        Size = 1;
    //ensure that there will be at least 8 bytes for user data
    //and 8 bytes for the _HEAP_ENTRY header
    //确保至少有8个字节的用户数据，8个字节的_HEAP_ENTRY头
    int RoundSize = (Size + 15) & 0xFFFFFF8;
    //blocks are contiguous 8‐byte chunks
    //连续的8字节chunks
    int BlockSize = RoundSize / 8;

    //The maximum allocation unit for the LFH 0x4000 bytes
    //0x4000字节(16K)是LFH最大分配单元
    if(Size > 0x4000)
    {
        _HEAP_LIST_LOOKUP *BlocksIndex;
        while(BlockSize >= BlocksIndex‐>ArraySize)
        {
            if(!BlocksIndex‐>ExtendedLookup)
            {
            BlockSize = BlocksIndex‐>ArraySize ‐ 1;
            break;
            }
            BlocksIndex = BlocksIndex‐>ExtendedLookup;
        }
        //gets the ListHint index based on the size requested
        //根据请求尺寸获取ListHint索引
        int Index = GetRealIndex(BlocksIndex, BlockSize);
        _LIST_ENTRY *hint = Heap‐>ListHints[Index];
        int DummyRet;
        chunk = RtlpAllocateHeap(Heap, Flags | 2, Size, RoundSize, Hint, &DummyRet);
        if(!chunk)
            return ERROR_NO_MEMORY;
        return chunk;
    }

    else
    {
    //check the status bitmap to see if the LFH has been enabled
    //查看位图的状态，LFH是否被激活
    int BitmapIndex = 1 << (RoundSize / 8) & 7;
    if(BitmapIndex & Heap‐>FrontEndStatusBitmap[RoundSize >> 6])
    {
        //Get the BucketIndex (as opposed to passing a _HEAP_BUCKET)
        //获取BucketIndex (而不是直接传递一个_HEAP_BUCKET)
        _LFH_HEAP LFH = Heap‐>FrontEndHeap;
        unsigned short BucketIndex = FrontEndHeapUsageData[BlockSize];
        chunk = RtlpLowFragHeapAllocFromContext(LFH,
        BucketIndex, Size, Flags | Heap‐>GlobalFlags);
    }
    if(!chunk)
        TryBackEnd();
    else
        return chunk;
    }
}

//后端
void *__fastcall RtlpAllocateHeap(_HEAP *Heap, int Flags, int Size, unsigned int RoundedSize, _LIST_ENTRY *ListHint, int *RetCode){
    void *Chunk = NULL;
    void *VirtBase;
    bool NormalAlloc = true;
    //covert the 8‐byte aligned amount of bytes
    // to 'blocks' assuring space for at least 8‐bytes user and 8‐byte header
    //转换8字节对齐总量到'blocks'单位，确保至少有8字节用户数据和8字节头部
    int BlockSize = RoundedSize / 8;
    if(BlocksSize < 2)
    {
        BlockSize = 2;
        RoundedSize += 8;
    }
    //32‐bit arch will only allocate less than 2GB
    //32位架构只能分配小于2GB的内存
    if(Size >= 0x7FFFFFFF)
        return 0;
    //if we have serialization enabled (i.e. use LFH) then go through some heuristics
    //如果串行标记被启用了，直接跳过启发式策略的设置
    if(!(Flags & HEAP_NO_SERIALIZE))
    {
        //This will activate the LFH if a FrontEnd allocation is enabled
        //如果前端分配被启用了，那么这就会激活LFH
        if (Heap‐>CompatibilityFlags & 0x30000000)
            RtlpPerformHeapMaintenance(vHeap);
    }

    //Virtual memory threshold is set to 0x7F000 in RtlCreateHeap()
    //在RtlCreateHeap中，虚分配阈值被设置为0x7F000
    if(BlockSize > Heap‐>VirtualMemoryThreshold)
    {
        //Adjust the size for a _HEAP_VIRTUAL_ALLOC_ENTRY
        //调整_HEAP_VIRTUAL_ALLOC_ENTRY的尺寸
        RoundedSize += 24;
        int Rand = (RtlpHeapGenerateRandomValue32() & 15) << 12;
        //Total size needed for the allocation
        //需要分配的尺寸总量
        size_t RegionSize = RoundedSize + 0x1000 + Rand;
        int Protect = PAGE_READWRITE;
        if(Flags & 0x40000)
            Protect = PAGE_EXECUTE_READWRITE;
        //if we can't reserve the memory, then we're going to abort
        //如果我们无力保留该大小的内存，就中止
        if(NtAllocateVirtualMemory(‐1, &VirtBase, 0, &RegionSize, MEM_RESERVE, Protect) < 0)
            return NULL;
        //Return at an random offset into the virtual memory
        //返回虚分配内存的一个随机偏移量
        _HEAP_VIRTUAL_ALLOC_ENTRY *Virt = VirtBase + Rand;
        //If we can't actually commit the memory, abort
        //如果我们实际上并不能提交该内存，也中止
        if(NtAllocateVirtualMemory(‐1, &Virt, 0, &RoundedSize, MEM_COMMIT, Protect) < 0)
        {
            RtlpSecMemFreeVirtualMemory(‐1, &VirtBase, &Rand, MEM_RESET);
            ++heap‐>Counters.CommitFailures;
            return NULL;
        }
        //Assign the size, flags, etc
        //赋予尺寸，标记等
        SetInfo(Virt);
        //add the virtually allocated chunk to the list ensuring
        //safe linking in at the end of the list
        //把虚分配chunk增加到链表中，确保其在链表的尾部被安全链入
        if(!SafeLinkIn(Virt))
            RtlpLogHeapFailure();
        Chunk = Virt + sizeof(_HEAP_VIRTUAL_ALLOC_ENTRY);
        return Chunk;
    }

    //attempt to determine if the LFH should be enabled for the size requested
    //试图判断为该请求尺寸的LFH是否要启用
    if(BlockSize >= Heap‐>FrontEndHeapMaximumIndex)
    {
        //if a size that could be serviced by the LFH is requested
        //attempt to set flags indicating bucket activation is possible
        //如果LFH可以服务的尺寸被请求到，就试图设置标志来指示bucket是可以激活的
        if(Size < 0x4000 && (Heap‐>FrontEndHeapType == 2 && !Heap‐>FrontEndHeap))
            Heap‐>CompatibilityFlags |= 0x20000000;
    }

    else if(Size < 0x4000)
    {
        //Heap‐>FrontEndHeapStatusBitmap has 256 possible entries
        //Heap‐>FrontEndHeapStatusBitmap有256个条目
        int BitmapIndex = BlockSize / 8;
        int BitPos = BlockSize & 7;
        //if the lfh isn't enabled for the size we're attempting to allocate
        //determine if we should enable it for the next go‐around
        //如果LFH没有为该尺寸激活，就判断我们是否要为后来的分配激活它
        if(!((1 << BitPos) & Heap‐>FrontEndHeapStatusBitmap[BitmapIndex]))
        {
            //increment the counter used to determine when to use the LFH
            //增加用来判断何时使用LFH的计数器
            unsigned short Count = Heap‐>FrontEndHeapUsageData[BlockSize] + 0x21;
            Heap‐>FrontEndHeapUsageData[BlockSize] = Count;
            //if there were 16 consecutive allocation or many allocations consider LFH
            //如果有16个或更多连续的分配，就考虑考虑LFH
            if((Count & 0x1F) > 0x10 || Count > 0xFF00)
            {
                //if the LFH has been initialized and activated, use it
                //如果LFH已经被初始化且激活了，就使用它
                _LFH_HEAP *LFH = NULL;
                if(Heap‐>FrontEndHeapType == 2)
                    LFH = heap‐>FrontEndHeap;
                //if the LFH is activated, it will return a valid index
                //如果LFH是激活的，它会返回一个合法的索引
                short BucketIndex = RtlpGetLFHContext(LFH, Size);
                if(BucketIndex != ‐1)
                {
                    //store the heap bucket index
                    //存储堆bucket索引
                    Heap‐>FrontEndHeapUsageData[BlockSize] = BucketIndex;
                    //update the bitmap accordingly
                    //更新位图的对应位
                    Heap‐>FrontEndHeapStatusBitmap[BitmapIndex] |= 1 << BitPos;
                }
                else if(Count > 0x10)
                {
                    //if we haven't been using the LFH, we will next time around
                    //如果我们此前未使用过LFH，我们下一次会使用它
                    if(!LFH)
                        Heap‐>CompatibilityFlags |= 0x20000000;
                }
            }
        }
    }

    //attempt to use the ListHints to optimally find a suitable chunk
    //试图使用ListHints来找到一个最合适的chunk
    _HEAP_ENTRY *HintHeader = NULL;
    _LIST_ENTRY *FreeListEntry = NULL;
    if(ListHint && ListHint‐>Flink)
        HintHeader = ListHint ‐ 8;
    else
    {
        FreeListEntry = RtlpFindEntry(Heap, BlockSize);
        if(&Heap‐>FreeLists == FreeListEntry)
        {
            //if the freelists are empty, you will have to extend the heap
            //如果freelists为空，就需要扩展堆
            _HEAP_ENTRY *ExtendedChunk = RtlpExtendHeap(Heap, aRoundedSize);
            if(ExtendedChunk)
                HintHeader = ExtendedChunk;
            else
                return NULL;
        }
        else
        {
            //try to use the chunk from the freelist
            //尝试使用freelist的chunk
            HintHeader = FreeListEntry ‐ 8;
            if(Heap‐>EncodeFlagMask)
                DecodeValidateHeader(HintHeader, Heap);
            int HintSize = HintHeader‐>Size;
            //if the chunk isn't big enough, extend the heap
            //如果chunk不够大，就扩展堆
            if(HintSize < BlockSize)
            {
                EncodeHeader(HintHeader, Heap);
                _HEAP_ENTRY *ExtendedChunk = RtlpExtendHeap(Heap, RoundedSize);
                if(ExtendedChunk)
                    HintHeader = ExtendedChunk;
                else
                    return NULL;
            }
        }
    }

    ListHint = HintHeader + 8;
    _LIST_ENTRY *Flink = ListHint‐>Flink;
    _LIST_ENTRY *Blink = ListHint‐>Blink;
    //safe unlinking or bust
    //要么安全链出，要么瞬间爆炸
    if(Blink‐>Flink != Flink‐>Blink || Blink‐>Flink != ListHint)
    {
        RtlpLogHeapFailure(12, Heap, ListHint, Flink‐>Blink, Blink‐>Flink, 0);
        return ERROR;
    }
    unsigned int HintSize = HintHeader‐>Size;
    _HEAP_LIST_LOOKUP *BlocksIndex = Heap‐>BlocksIndex;
    if(BlocksIndex)
    {
        //this will traverse the BlocksIndex looking for
        //an appropriate index, returning ArraySize ‐ 1
        //for a chunk that doesn't have a ListHint (or is too big)
        //追溯BlocksIndex来找到一个合适的索引，如果对一个chunk来说
        //没有对应的ListHint(或尺寸过巨)就返回ArraySize ‐ 1
        HintSize = SearchBlocksIndex(BlocksIndex);
    }
    //updates the ListHint linked lists and Bitmap used by the BlocksIndex
    //更新ListHint链表以及BlocksIndex所用的位图
    RtlpHeapRemoveListEntry(Heap, BlocksIndex, RtlpHeapFreeListCompare,
    ListHint, HintSize, HintHeader‐>Size);
    //unlink the entry from the linked list
    //safety check above, so this is OK
    //从链表中断链chunk，在之前已经检查过了，所以这里不检查也OK
    Flink‐>Blink = Blink;
    Blink‐>Flink = Flink;

    if( !(HintHeader‐>Flags & 8) || RtlpCommitBlock(Heap, HintHeader))
    {
        //Depending on the flags and the unused bytes the header
        //will set the UnusedBytes and potentially alter the 'next'
        //chunk directly after the one acquired from the FreeLists
        //which migh result in a call to RtlpCreateSplitBlock()
        //根据标志和未使用的字节数，头部会设置UnusedBytes并潜在的改变
        //从FreeLists获取到的chunk的下一个chunk，引起对RtlpCreateSplitBlock()的调用
        int UnusedBytes = HintHeader‐>Size ‐ RoundedSize;
        bool OK = UpdateHeaders(HintHeader);
        if(OK)
        {
            //We've updated all we need, MEM_ZERO the chunk
            //if needed and return to the calling function
            //我们已经更新了所有需要的，MEM_ZERO该chunk如果需要的话
            //返回给调用函数
            Chunk = HintHeader + 8;
            if(Flags & 8)
            memset(Chunk, 0, HintHeader‐>Size ‐ 8);
            return Chunk;
        }
        else
            return ERROR;
    }
    else
    {
        RtlpDeCommitFreeBlock(Heap, HintHeader, HintHeader‐>Size, 1);
        return ERROR;
    }
}

//前端
void *RtlpLowFragHeapAllocFromContext(_LFH_HEAP *LFH, unsigned short BucketIndex, int Size, char Flags){
    _HEAP_BUCKET *HeapBucket = LFH‐>Buckets[BucketIndex];
    _HEAP_ENTRY *Header = NULL;
    int VirtAffinity = NtCurrentTeb()‐>HeapVirtualAffinity ‐ 1;
    int AffinityIndex = VirtAffinity;
    if(HeapBucket‐>UseAffinity)
    {
        if(VirtAffinity < 0)
            AffinityIndex = RtlpAllocateAffinityIndex()  ;
        //Initializes all global variables used for Affinity based allocations
        //初始化基于亲和性分配的所有全局变量
        AffinitySetup();
    }

    int SizeIndex = HeapBucket‐>SizeIndex;
    _HEAP_LOCAL_SEGMENT_INFO *LocalSegInfo;
    if(AffinityIndex)
        LocalSegInfo = LFH‐>AffinitizedInfoArrays[SizeIndex][AffinityIndex ‐ 1];
    else
        LocalSegInfo = LFH‐>SegmentInfoArrays[SizeIndex];
    _HEAP_SUBSEGMENT *ActiveSubseg = LocalSegInfo‐>ActiveSubsegment;

    //This is actually done in a loop but left out for formatting reasons
    //The LFH will do its best to attempt to service the allocation before giving up
    //实际上由循环完成，但因为格式问题没有保留
    //在放弃之前，LFH将尽最大努力来服务内存分配
    if(!ActiveSubseg)
        goto check_cache;
    _INTERLOCK_SEQ *AggrExchg = ActiveSubseg‐>AggregateExchg;
    //ensure the values are acquired atomically
    //确保原子地获取该值
    int Depth, Hint;
    AtomicAcquireDepthHint(AggrExchg, &Depth, &Hint);
    //at this point we should have acquired a sufficient subsegment and can
    //now use it for an actual allocation, we also want to make sure that
    //the UserBlocks has chunks left along w/ a matching subsegment info structures
    //此时我们已经获取到了合适的subsegment，现在可以用来处理实际的分配了
    //我们也要确保UserBlocks还有剩余的chunks
    _HEAP_USERDATA_HEADER *UserBlocks = ActiveSubseg‐>UserBlocks;
    //if the UserBlocks haven't been allocated or the
    //_HEAP_LOCAL_SEGMENT_INFO structures don't match
    //attempt to acquire a Subsegment from the cache
    //如果UserBlocks尚未被分配或者_HEAP_LOCAL_SEGMENT_INFO结构不匹配
    //尝试从缓存中获取一个Subsegment
    if(!UserBlocks || ActiveSubseg‐>LocalInfo != LocalSegInfo)
        goto check_cache;

    //Instead of using the FreeEntryOffset to determine the index
    //of the allocation, use a random byte to start the search
    //不再使用FreeEntryOffset来决定分配的索引，而是使用随机字节作为搜索的起始位置
    short LFHDataSlot = NtCurrentTeb()‐>LowFragHeapDataSlot;
    BYTE Rand = RtlpLowFragHeapRandomData[LFHDataSlot];
    NtCurrentTeb()‐>LowFragHeapDataSlot++;

    //we need to know the size of the bitmap we're searching
    //搜索前我们需要知晓位图的尺寸
    unsigned int BitmapSize = UserBlocks‐>BusyBitmap‐>SizeOfBitmap;
    //Starting offset into the bitmap to search for a free chunk
    //从位图的StartOffset偏移处开始搜索free chunk
    unsigned int StartOffset = Rand;
    void *Bitmap = UserBlocks‐>BusyBitmap‐>Buffer;
    if(BitmapSize < 0x20)
        StartOffset = (Rand * BitmapSize) / 0x80;
    else
        StartOffset = SafeSearchLargeBitmap(UserBlocks‐>BusyBitmap‐>Buffer);

    //Rotate the bitmap (as to not lose items) to start
    //at our randomly chosen offset
    //循环遍历位图，从随机选择的偏移开始
    int RORBitmap = __ROR__(*Bitmap, StartOffset);
    //since we're looking for 0's (FREE chunks)
    //we'll invert the value due to how the next instruction works
    //因为我们要找0的位(FREE chunks)
    //所以我们会翻转该值，出于下一个指令的效果
    int InverseBitmap = ~RORBitmap;
    //these instructions search from low order bit to high order bit looking for a 1
    //这些指令从低位到高位查找1
    //since we inverted our bitmap, the 1s will be 0s (BUSY) and the 0s will be 1s (FREE)
    //因为我们翻转了位图，所以1实际上是0(Busy)，而0实际上是1(Free)
    // <‐‐ search direction
    //搜索方向
    //H.O                                                 L.O
    //‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐
    //| 1 | 1 | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 1 | 0 | 0 | 0
    //‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐‐
    //the following code would look at the bitmap above, starting at L.O
    //looking for a bit position that contains the value of one, and storing that index
    //下面的代码会查看上面的位图，从L.O开始找到一个包含值为1的位，存储该索引值
    int FreeIndex;
    __asm{bsf FreeIndex, InverseBitmap};

    //shows the difference between the start search index and
    //the actual index of the first free chunk found
    //展示起始搜索索引和找到的第一个空闲chunk实际索引的区别
    int Delta = ((BYTE)FreeIndex + (BYTE)StartOffset) & 0x1F;
    //now that we've found the index of the chunk we want to allocate
    //mark it as 'used'; as it previously was 'free'
    //现在我们已经找到了想要分配的chunk的索引，标记为'used'，此前它是'free'
    *Bitmap |= 1 << Delta;
    //get the location (current index into the UserBlock)
    //获取位置(UserBlock的当前索引)
    int NewHint = Delta + sizeof(_HEAP_USERDATA_HEADER) * (Bitmap ‐ UserBlocks‐>BusyBitmap‐>Buffer);
    AggrExchg.Depth = Depth ‐ 1;
    AggrExchg.Hint = NewHint;
    //get the chunk header for the chunk that we just allocated
    //获取刚刚分配的chunk头
    Header = (_HEAP_ENTRY)UserBlocks + UserBlocks‐>FirstAllocationOffset + (NewHint * UserBlocks‐>BlockStride);

    if(Header‐>UnusedBytes & 0x3F)
        RtlpReportHeapFailure(14, LocalSegInfo‐>LocalData‐>LowFragHeap‐>Heap, Header, 0, 0, 0);
    if(Header)
    {
        if(Flags & 8)
            memset(Header + 8, 0, HeapBucket‐>BlockUnits ‐ 8);
        //set the unused bytes if there are any
        //设置未使用字节数，如果有的话
        int Unused = (HeapBucket‐>BlockUnits * 8) ‐ Size;
        Header‐>UnusedBytes = Unused | 0x80;
        if(Unused >= 0x3F)
        {
            _HEAP_ENTRY *Next = Header + (8 * HeapBucket‐>BlockUnits) ‐ 8;
            Next‐>PreviousSize = Unused;
            Header‐>UnusedBytes = 0xBF;
        }
        return Header + sizeof(_HEAP_ENTRY);
    }

    _HEAP_SUBSEGMENT *NewSubseg = NULL;
    NewSubseg = SearchCache(LocalSegInfo);

    int PageShift, BlockSize;
    int TotalBlocks = LocalSegInfo‐>Counters‐>TotalBlocks;
    //Based on the amount of chunks allocated for a given
    //_HEAP_LOCAL_SEGMENT_INFO structure, and the _HEAP_BUCKET
    //size and affinity formulate how many pages to allocate
    //对给定_HEAP_LOCAL_SEGMENT_INFO结构，基于分配chunks的总量和_HEAP_BUCKET
    //尺寸和亲和性来计算需要分配多少个页面
    CalculateUserBlocksSize(HeapBucket, &PageShift, &TotalBlocks, &BlockSize);

    //If we've seen enough allocations or the number of pages
    //to allocate is very large, we're going to set a guard page
    //after the UserBlocks container
    //如果分配量足够多或者分配的页数非常大，那么就需要在UserBlocks容器之后设置一个守护页
    bool SetGuard = false;
    if(PageShift == 0x12 || TotalBlocks >= 0x400)
        SetGuard = true;
    //Allocate memory for a new UserBlocks structure
    //为新的UserBlocks结构分配内存
    _HEAP_USERDATA_HEADER *UserBlock = RtlpAllocateUserBlock(LFH, PageShift, BlockSize + 8, SetGuard);
    if(UserBlock == NULL)
        return 0;
    
    //See if there are previously deleted Subsegments to use
    //查看是否存在此前删除的Subsegments可以用
    NewSubseg = CheckDeletedSubsegs(LocalSegInfo);
    if(!NewSubseg)
        NewSubseg = RtlpLowFragHeapAllocateFromZone(LFH, AffinityIndex);
    //if we can't get a subsegment we can't fulfill this allocation
    //如果我们获取不到subsegment，就无法满足分配
    if(!NewSubseg)
        return;

    //Initialize the Subsegment, which will divide out the
    //chunks in the UserBlock by writing a _HEAP_ENTRY header
    //every HeapBucket‐>BlockUnits bytes
    //初始化Subsegment，在UserBlock中划分chunks
    //每HeapBucket‐>BlockUnits字节大小的chunk，就写一个_HEAP_ENTRY头
    NewSubseg‐>AffinityIndex = AffinityIndex;
    RtlpSubSegmentInitialize(LFH, NewSubseg, UserBlock, RtlpBucketBlockSizes[HeapBucket‐>SizeIndex], SizeIndex ‐ 8, HeapBucket);

    UserBlock‐>Signature = 0xF0E0D0C0;
    LocalSegInfo‐>ActiveSubsegment = NewSubseg;
    //same logic seen in previous code
    //与前面代码逻辑相同
    goto use_active_subsegment;
}

_HEAP_USERDATA_HEADER *RtlpAllocateUserBlock(_LFH_HEAP *LFH, unsigned __int8 PageShift, int ChunkSize, bool SetGuardPage){
    int ByteSize = 1 << PageShift;
    if(ByteSize > 0x78000)
        ByteSize = 0x78000;
    UserBlocks = CheckCache(LFH‐>UserBlockCache, PageShift);
    if(!UserBlocks)
        UserBlocks = RtlpAllocateUserBlockFromHeap(LFH‐>Heap, PageShift, ChunkSize, SetGuardPage);
    UpdateCounters(LFH‐>UserBlockCache, PageShift);
    return UserBlocks;
}

_HEAP_USERDATA_HEADER *RtlpAllocateUserBlockFromHeap(_HEAP *Heap, PageShift, ChunkSize, SetGuardPage){
    int ByteSize = 1 << PageShift;
    if(ByteSize > 0x78000)
        ByteSize = 0x78000;
    int SizeNoHeader = ByteSize ‐ 8;
    int SizeNoHeaderOrig = SizeNoHeader;
    //Add extra space for the guard page
    //为守护页增加额外空间
    if(SetGuardPage)
        SizeNoHeader += 0x2000;
    _HEAP_USERDATA_HEADER *UserBlocks = RtlAllocatHeap(Heap, 0x800001, SizeNoHeader);
    if(!UserBlocks)
        return NULL;

    if(!SetGuardPage)
    {
        UserBlocks‐>GuardPagePresent = false;
        return UserBlocks;
    }
    //add in a guard page so that a sequential overflow will fail
    //as PAGE_NOACCESS will raise a AV on read/write
    //增加一个守护页，以致于连续溢出会因为PAGE_NOACCESS抛出读写请求的访问违例异常而失败
    int GuardPageSize = 0x1000;
    int AlignedAddr = (UserBlocks + SizeNoHeaderOrig + 0xFFF) & 0xFFFFF000;
    int NewSize = (AlignedAddr ‐ UserBlocks) + GuardPageSize;
    //reallocate the memory
    //重新分配内存
    UserBlocks = RtlReAllocateHeap(Heap, 0x800001, UserBlocks, NewSize);
    //Sets the last page (0x1000 bytes) of the memory chunk to PAGE_NOACCESS (0x1)
    //http://msdn.microsoft.com/en‐us/library/windows/desktop/aa366786(v=vs.85).aspx
    //设置内存chunk的最后一页(0x1000字节)为PAGE_NOACCESS权限(0x1)
    ZwProtectVirtualMemory(‐1, &AlignedAddr, &GuardPageSize, PAGE_NOACCESS, &output);
    //Update the meta data for the UserBlocks
    //更新UserBlocks的元数据
    UserBlocks‐>GuardPagePresent = true;
    UserBlocks‐>PaddingBytes = (SizeNoHeader ‐ GuardPageSize) ‐ SizeNoHeaderOrig;
    UserBlocks‐>SizeIndex = PageShift;
    return UserBlocks;

}

_HEAP_SUBSEGMENT *RtlpLowFragHeapAllocateFromZone(_LFH_HEAP *LFH, int AffinityIndex){
    int LocalIndex = AffinityIndex * sizeof(_HEAP_LOCAL_DATA);
    _LFH_BLOCK_ZONE *Zone = NULL;
    _LFH_BLOCK_ZONE *NewZone;
    char *FreePtr = NULL;
    try_zone:
    //if there aren’t any CrtZones allocate some
    //如果没有CrtZones
    Zone = LFH‐>LocalData[LocalIndex]‐>CrtZone;
    if(Zone)
    {
        //this is actually done atomically
        //实际上原子的完成
        FreePtr = Zone‐>FreePointer;
        if(FreePtr + 0x28 < Zone‐>Limit)
        {
            AtomicIncrement(&Zone‐>FreePointer, 0x28);
            return FreePtr;
        }
    }

    //allocate 1016 bytes for _LFH_BLOCK_ZONE structs
    //为_LFH_BLOCK_ZONE结构分配1016字节
    NewZone = RtlAllocateHeap(LFH‐>Heap, 0x800000, 0x3F8);
    if(!NewZone)
        return 0;
    _LIST_ENTRY *ZoneHead = &LFH‐>SubSegmentZones;
    if(ZoneHead‐>Flink‐>Blink == ZoneHead && ZoneHeader‐>Blink‐>Flink == ZoneHead)
    {
        LinkIn(NewZone);
        NewZone‐>Limit = NewZone + 0x3F8;
        NewZone‐>FreePointer = NewZone + sizeof(_LFH_BLOCK_ZONE);
        //set the current localdata
        //设置当前的localdata
        LFH‐>LocalData[LocalIndex]‐>CrtZone = NewZone;
        goto try_zone;
    }
    else
    {
        //fast fail!
        //光速失败！
        __asm{int 0x29};
    }
}

int RtlpSubSegmentInitialize(_LFH_HEAP *LFH, _HEAP_SUBSEGMENT *NewSubSeg, _HEAP_USERDATA_HEADER *UserBlocks, int ChunkSize, int SizeNoHeader, _HEAP_BUCKET *HeapBucket){
    _HEAP_LOCAL_SEGMENT_INFO *SegmentInfo;
    _INTERLOCK_SEQ *AggrExchg = NewSubSeg‐>AggregateExchg;
    int AffinityIndex = NewSubSeg‐>AffinityIndex;
    int SizeIndex = HeapBucket‐>SizeIndex;
    //get the proper _HEAP_LOCAL_SEGMENT_INFO based on affinity
    //根据亲和性找到合适的_HEAP_LOCAL_SEGMENT_INFO
    if(AffinityIndex)
        SegmentInfo = LFH‐>AffinitizedInfoArrays[SizeIndex][AffinityIndex ‐ 1];
    else
        SegmentInfo = LFH‐>SegmentInfoArrays[SizeIndex];

    unsigned int TotalSize = ChunkSize + sizeof(_HEAP_ENTRY);
    unsigned short BlockSize = TotalSize / 8;
    //this will be the number of chunks in the UserBlocks
    //UserBlocks的chunks数量
    unsigned int NumOfChunks = (SizeNoHeader ‐ sizeof(_HEAP_USERDATA_HEADER)) / TotalSize;
    //Set the _HEAP_SUBSEGMENT and denote the end
    //设置_HEAP_SUBSEGMENT，指示尾部
    UserBlocks‐>SfreeListEntry.Next = NewSubSeg;
    char *UserBlockEnd = UserBlock + SizeNoHeader;
    //Get the offset of the first chunk that can be allocated
    //Windows 7 just used 0x2 (2 * 8), which was the size
    //of the _HEAP_USERDATA_HEADER
    //获取第一个可以被分配的chunk的偏移
    //Windows 7直接使用0x2(2 * 8)，它是_HEAP_USERDATA_HEADER的尺寸
    unsigned int FirstAllocOffset = ((((NumOfChunks + 0x1F) / 8) & 0x1FFFFFFC) +
    sizeof(_HEAP_USERDATA_HEADER)) & 0xFFFFFFF8;
    UserBlocks‐>FirstAllocationOffset = FirstAllocOffset;

    //if permitted, start writing chunk headers every TotalSize bytes
    //如果允许，就每TotalSize字节写一个chunk头
    if(UserBlocks + FirstAllocOffset + TotalSize < UserBlockEnd)
    {
        _HEAP_ENTRY *CurrHeader = UserBlocks + FirstAllocOffset;
        do
        {
            //set the encoded lfh chunk header, by XORing certain
            //values. This is how a Subsegment can be derived in RtlpLowFragHeapFree
            //设置编码的lfh chunk头，通过异或某个具体的值来计算
            //这就是RtlpLowFragHeapFree获取Subsegment的方式
            *(DWORD)CurrHeader = (DWORD)Heap‐>Entry ^ NewSubSeg ^
            RtlpLFHKey ^ (CurrHeader >> 3);
            //FreeEntryOffset replacement
            //FreeEntryOffset替代
            CurrHeader‐>PreviousSize = Index;
            //denote as a free chunk in the LFH
            //在LFH中指示一个free chunk
            CurrHeader‐>UnusedBytes = 0x80;
            //increment the header and counter
            //增加header和counter
            CurrHeader += TotalSize;
            Index++;
        }
        while((CurrHeader + TotalSize) < UserBlockEnd);
    }

    //Initialize the bitmap and zero out its memory (Index == Number of Chunks)
    //初始化位图，零化内存(Index == chunk数量)
    RtlInitializeBitMap(&UserBlocks‐>BusyBitmap; UserBlocks‐>BitmapData, Index);
    char *Bitmap = UserBlocks‐>BusyBitmap‐>Buffer;
    unsigned int BitmapSize = UserBlocks‐>BusyBitmap‐>SizeOfBitMap;
    memset(Bitmap, 0, (BitmapSize + 7) / 8);
    //This will set all the members of this structure
    //to the appropriate values derived from this func
    //associating UserBlocks and SegmentInfo
    //这将设置该结构所有的成员值，这些值来源于关联的UserBlocks和SegmentInfo
    UpdateSubsegment(NewSubSeg,SegmentInfo, UserBlocks);

    //Update the random values each time a _HEAP_SUBSEGMENT is init
    //每次_HEAP_SUBSEGMENT初始化时，更新随机值
    int DataSlot = NtCurrentTeb()‐>LowFragHeapDataSlot;
    //RtlpLowFragHeapRandomData is generated in
    //RtlpInitializeLfhRandomDataArray() via RtlpCreateLowFragHeap
    //RtlpLowFragHeapRandomData在RtlpInitializeLfhRandomDataArray()中通过
    //RtlpCreateLowFragHeap生成
    short RandWord = GetRandWord(RtlpLowFragHeapRandomData, DataSlot);
    NtCurrentTeb()‐>LowFragHeapDataSlot = (DataSlot + 2) & 0xFF;
    //update the depth to be the amount of chunks we created
    //更新depth为创建的chunks的总量
    _INTERLOCK_SEQ NewAggrExchg;
    NewAggrExchg.Depth = Index;
    NewAggrExchg.Hint = RandWord % (Index << 16);
    //swap of the old and new aggr_exchg
    //交换aggr_exchg的新旧值
    int Result = _InterlockedCompareExchange(&NewSubSeg‐>AggregateExchg,
    NewAggrExchg, AggrExchg);
    //update the previously used SHORT w/ new random values
    //使用新的随机值更新以前用到的SHORT
    if(!(RtlpLowFragHeapGlobalFlags & 2))
    {
        unsigned short Slot = NtCurrentTeb()‐>LowFragHeapDataSlot;
        //ensure that all bytes are unsigned
        //确保所有字节都是无符号的
        int Rand1 = RtlpHeapGenerateRandomValue32() & 0x7F7F7F7F;
        int Rand2 = RtlpHeapGenerateRandomValue32() & 0x7F7F7F7F;
        //reassign the random data so it’s not the same for each Subsegment
        //重新赋予随机数，因此每个Subsegment都不一样
        RtlpLowFragHeapRandomData[Slot] = Rand1;
        RtlpLowFragHeapRandomData[Slot+1] = Rand2;
    }
    return result;
}