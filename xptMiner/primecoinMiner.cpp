#include"global.h"
#include <assert.h>
#include <exception>
//#define BNUM_MAX_ACCURACY	(2000/64)
//
//typedef struct  
//{
//	uint8 size;
//	uint64 d[BNUM_MAX_ACCURACY];
//}bnum_t;
//
//#ifdef _WIN64
//#define bnum_mul64ov(_overflow, _a, _b) (_umul128(_a, _b, &_overflow))
//#endif
//
//void bnum_set(bnum_t* bnum, uint32 v)
//{
//	bnum->d[0] = v;
//	bnum->size = 1;
//}
//
//void bnum_multiplyW32(bnum_t* bnum, uint32 b)
//{
//	
//}

void primecoin_process(minerPrimecoinBlock_t* block)
{
	// not needed
	
}

class CSieve
{
public:
    static const int sieveSize = 1000000;

private:
	static const int largestPrimeInTable = 1000;

    static std::vector<int> primeTable;
    static bool primeTableInited;
    char pSieve[sieveSize];
    int _index;

    static void InitPrimeTable( minerRiecoinBlock_t* block )
    {
        if( primeTableInited )
            return;
        EnterCriticalSection(&block->cs_work);
		{            
            if( primeTableInited )
                return;
            primeTableInited = true;
            primeTable.push_back(2);
            for( int i = 3; i <= largestPrimeInTable; i += 2 )
            {
                if( isPrime(i) )
                    primeTable.push_back(i);
            }
        }
		LeaveCriticalSection(&block->cs_work);
    }
    static bool isPrime( int candidate )
    {
        for( unsigned int i = 0; i < primeTable.size(); i++ )
        {
            const int prime = primeTable[i];
            if( prime * prime > candidate )
                return true;
            if( (candidate % prime) == 0 )
                return false;
        }
        return true;
    }

public:
    void init( CBigNum const &base, minerRiecoinBlock_t* block )
    {
        InitPrimeTable(block);
        /*if( pSieve == NULL )
{
pSieve = (char *)malloc(sieveSize);
}*/
        memset( pSieve, true, sieveSize );
        for( unsigned int primeIndex = 0; primeIndex < primeTable.size(); primeIndex++ )
        {
            int prime = primeTable[primeIndex];
            for( int sieveIndex = prime - (base % prime).getint(); sieveIndex < sieveSize; sieveIndex += prime )
            {
                pSieve[sieveIndex] = false;
            }
        }
        _index = 4;
    }
    static void dumpPrimeTable( minerRiecoinBlock_t* block )
    {
        InitPrimeTable(block);
        for( unsigned int primeIndex = 0; primeIndex < primeTable.size(); primeIndex++ )
        {
            printf(" Prime %d: %d\n", primeIndex, primeTable[primeIndex]);
        }
    }

    int getNext( void )
    {
        if( _index >= sieveSize - 16 )
        {
            return -1;
        }
        while( 1 )
        {
            _index++;
            if( _index >= sieveSize - 16 )
            {
                return -1;
            }
            if( pSieve[_index] && pSieve[_index+4] &&
                pSieve[_index+6] && pSieve[_index+10] &&
                pSieve[_index+12] && pSieve[_index+16] )
                return _index;
        }
    }

};
std::vector<int> CSieve::primeTable;
bool CSieve::primeTableInited;

const int zeroesBeforeHashInPrime = 8;
unsigned int generatePrimeBase( CBigNum &bnTarget, uint256 hash, unsigned int compactBits )
{
    bnTarget = 1;
    bnTarget <<= zeroesBeforeHashInPrime;

    for ( int i = 0; i < 256; i++ )
    {
        bnTarget = (bnTarget << 1) + (hash.Get32() & 1);
        hash >>= 1;
    }
    CBigNum nBits;
    nBits.SetCompact(compactBits);
    if( nBits > nBits.getuint() ) // the protocol stores a compact big int so it supports larger values, but this version of the client does not
    {
        nBits = (unsigned int)-1; // saturate diff at (2**32) - 1, this should be enough for some years ;)
    }
    unsigned int trailingZeros = nBits.getuint() - 1 - zeroesBeforeHashInPrime - 256;
    bnTarget <<= trailingZeros;
    return trailingZeros;
}

void primecoinBlock_generateHeaderHash(minerRiecoinBlock_t* primecoinBlock, uint8 hashOutput[32]) {
   uint8 blockHashDataInput[608];
   memcpy(blockHashDataInput, primecoinBlock, 608);
   sha256_ctx ctx;
   sha256_init(&ctx);
   sha256_update(&ctx, (uint8*)blockHashDataInput, 608);
   sha256_final(&ctx, hashOutput);
   /*sha256_init(&ctx); // is this line needed?
   sha256_update(&ctx, hashOutput, 32);
   sha256_final(&ctx, hashOutput);*/
}

void riecoin_process(minerRiecoinBlock_t* block)
{
	// do the riecoin stuff
    unsigned int nExtraNonce = 0;
    CSieve mySieve;
    int previousDelta;
    int candidateDelta = -1;
	int64 accumulatedDelta = 0;
	try
	{
		while(true) {
			
			std::vector<unsigned char> headerHash;
			for(int i = 0; i < 32; i++)
			{
				headerHash.push_back(block->blockHash[i]);
			}
			uint256 blockHash2 = uint256(headerHash);
			
			CBigNum bnTarget, bnBase;
			generatePrimeBase( bnBase, blockHash2, block->nBits );

			mySieve.init(bnBase, block);

			candidateDelta		= -1;
			previousDelta		= 0;
			accumulatedDelta	= 0;
			
			while(true)
			{
				if( block->height != monitorCurrentBlockHeight )
				{
					return;
				}

				int i, isPrimeResult = 0;
				const int TRIES = 65536;

				for ( i = 0; i < TRIES; i++ )
				{					
					candidateDelta = mySieve.getNext();
					if( candidateDelta < 0 )
						break;
					bnTarget = bnBase + candidateDelta;
					isPrimeResult = BN_is_prime_fasttest( &bnTarget, 4, NULL, NULL, NULL, 1);
					totalCollisionCount++;
					if ( isPrimeResult == 1 )
					{
						break;
					}
				}				

				// Check if something found
				if ( candidateDelta >= 0 && i != TRIES)
				{
					bnTarget += 4;
					if( BN_is_prime_fasttest( &bnTarget, 4, NULL, NULL, NULL, 1) == 1 ) {
						// we accept quintuplets
						totalCollisionCount++;
						bnTarget += 2;
					if( BN_is_prime_fasttest( &bnTarget, 4, NULL, NULL, NULL, 1) == 1 ) {
						totalCollisionCount++;
						// we send 3 tuples because the server accepts it
						// if this thing is bigger than the server will reward it as the bigger prime
						EnterCriticalSection(&block->cs_work);
						uint256 delta = candidateDelta + accumulatedDelta;
						memcpy(block->nOffset, &delta, sizeof(delta));
						xptMiner_submitShare(block);
						totalShareCount++;
						LeaveCriticalSection(&block->cs_work);
					} }
				}

				// Meter range/sec
				if( candidateDelta > -1 )
				{
					previousDelta = candidateDelta;
				}            

				// Check for stop or if block needs to be rebuilt
				if( candidateDelta < 0 )
				{
					bnBase += mySieve.sieveSize;
					accumulatedDelta += mySieve.sieveSize;
					mySieve.init(bnBase, block);

					candidateDelta = -1;
					previousDelta = 0;
				}
			} // end infinite loop
		} 
	}
	catch (std::exception& e)
    {
        printf("riecoinMining thread terminated\n");
        return;
    }
}