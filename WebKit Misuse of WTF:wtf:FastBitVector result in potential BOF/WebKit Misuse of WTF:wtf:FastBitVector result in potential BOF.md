## WebKit Misuse of WTF/wtf/FastBitVector result in potential BOF

What is discribed in this archive existed a long time in versions of WebKit project. The newest commit ID is 5f48410.

WebKit Source/WTF/wtf/FastBitVector.cpp:

```c++
void FastBitVectorWordOwner::resizeSlow(size_t numBits)
{
    size_t newLength = fastBitVectorArrayLength(numBits);
    
    // Use fastCalloc instead of fastRealloc because we expect the common
    // use case for this method to be initializing the size of the bitvector.
    
    uint32_t* newArray = static_cast<uint32_t*>(fastCalloc(newLength, sizeof(uint32_t)));
    memcpy(newArray, m_words, arrayLength() * sizeof(uint32_t));
    if (m_words)
        fastFree(m_words);
    m_words = newArray;
}
```

The third argument of memcpy is `arrayLength() * sizeof(uint32_t)`, in which `arrayLength()` is a function referencing `this->m_numBits`(the old one). Thus if `oldArrayLength > newArrayLength`, the memcpy would might cause a potential BOF since `__builtin___memcpy_chk` relies on platforms eg GNUC . 

The original purpose of this function is to be `initializing` the size of the bitvector. If properly used, nothing would happen in the context. But not.



Luckily, FastBitVector is not referenced by many functions in WebKit project.

1. JavaScriptCore/bytecode/BytecodeLivenessAnalysisInlines.h:

   ```c++
   template<typename DerivedAnalysis>
   template<typename Graph>
   inline FastBitVector BytecodeLivenessPropagation<DerivedAnalysis>::getLivenessInfoAtBytecodeOffset(Graph& graph, unsigned bytecodeOffset)
   {
       ...
       FastBitVector out;
       out.resize(block->out().numBits());
       ...
   }
   ```

   That's a proper use of a FastBitVector.

2. WTF/wtf/FastBitVector.h

   ```
   class FastBitVectorWordOwner {
   public:
       ...
       void resize(size_t numBits)
       {
           if (arrayLength() != fastBitVectorArrayLength(numBits))
               resizeSlow(numBits);
           m_numBits = numBits;
       }
   ```

   Here's a `misuse` of `FastBitVector::resizeSlow` because the method `FastBitVectorWordOwner::resize` is not a initialization. This encapsulation could be misunderstanding and dangerous and is correspond to the buffer overflow situation previously decribed. 

FastBinVector is rarely uesd in WebKit, while it is in WTF as an fundation class library,It's unknowable that it could be used in other products. I suggest that there could be a fix towards this one.


This bug was credit by ADLab of Venustech. However NVD could have overated its impact.
