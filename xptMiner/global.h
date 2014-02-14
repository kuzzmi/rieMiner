#pragma comment(lib,"Ws2_32.lib")
#include<Winsock2.h>
#include<ws2tcpip.h>
#include<stdio.h>
#include<time.h>
#include<stdlib.h>

#include"jhlib.h" // slim version of jh library
#include "includes\uint256.h"

#include"openCL.h"

// connection info for xpt
typedef struct  
{
	char* ip;
	uint16 port;
	char* authUser;
	char* authPass;
}generalRequestTarget_t;

#include"xptServer.h"
#include"xptClient.h"


#include<openssl/bn.h>
#include "sha2.h"

// our own improved versions of BN functions
BIGNUM *BN2_mod_inverse(BIGNUM *in,	const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
int BN2_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor);
int BN2_num_bits(const BIGNUM *a);
int BN2_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN2_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN2_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

#define fastInitBignum(bignumVar, bignumData) \
	bignumVar.d = (BN_ULONG*)bignumData; \
	bignumVar.dmax = 0x200/4; \
	bignumVar.flags = BN_FLG_STATIC_DATA; \
	bignumVar.neg = 0; \
	bignumVar.top = 1; 

// original primecoin BN stuff
#include"uint256.h"
#include"bignum2.h"

#include"sph_keccak.h"
#include"sph_metis.h"
#include"sph_shavite.h"

#include"transaction.h"



// global settings for miner
typedef struct  
{
	generalRequestTarget_t requestTarget;
	uint32 protoshareMemoryMode;
	uint32 payload;
	// GPU
	bool useGPU; // enable OpenCL
	// GPU (MaxCoin specific)

}minerSettings_t;

extern minerSettings_t minerSettings;

#define PROTOSHARE_MEM_512		(0)
#define PROTOSHARE_MEM_256		(1)
#define PROTOSHARE_MEM_128		(2)
#define PROTOSHARE_MEM_32		(3)
#define PROTOSHARE_MEM_8		(4)

// block data struct

typedef struct  
{
	// block header data (relevant for midhash)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// birthday collision
	uint32	birthdayA;
	uint32	birthdayB;
	uint32	uniqueMerkleSeed;

	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerProtosharesBlock_t;

typedef struct  
{
	// block header data
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerScryptBlock_t;

typedef struct  
{
	// block header data
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
	// found chain data
	// todo
}minerPrimecoinBlock_t;

typedef struct  
{
	CRITICAL_SECTION cs_work;
	// block header data
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	
	uint32	nBits;
	uint32	timestamp;	
	uint8	nOffset[32];
		
	uint8	blockHash[32];
	uint32	nOffsetLength;	
	uint32	height;
	// found chain data
	// todo
}minerRiecoinBlock_t;



typedef struct  
{
	// block data (order and memory layout is important)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// remaining data
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerMetiscoinBlock_t; // identical to scryptBlock

typedef struct  
{
	// block data (order and memory layout is important)
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	nTime;
	uint32	nBits;
	uint32	nonce;
	// remaining data
	uint32	uniqueMerkleSeed;
	uint32	height;
	uint8	merkleRootOriginal[32]; // used to identify work
	uint8	target[32];
	uint8	targetShare[32];
}minerMaxcoinBlock_t; // identical to scryptBlock

#include"scrypt.h"
#include"algorithm.h"
#include"openCL.h"

void xptMiner_submitShare(minerProtosharesBlock_t* block);
void xptMiner_submitShare(minerScryptBlock_t* block);
void xptMiner_submitShare(minerPrimecoinBlock_t* block);
void xptMiner_submitShare(minerMetiscoinBlock_t* block);
void xptMiner_submitShare(minerMaxcoinBlock_t* block);
void xptMiner_submitShare(minerRiecoinBlock_t* block);

// stats
extern volatile uint32 totalCollisionCount;
extern volatile uint32 totalShareCount;
extern volatile uint32 totalRejectedShareCount;

extern volatile uint32 monitorCurrentBlockHeight;
extern volatile uint32 monitorCurrentBlockTime;