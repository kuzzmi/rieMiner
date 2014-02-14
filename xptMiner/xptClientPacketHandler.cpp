#include"global.h"

/*
 * Called when a packet with the opcode XPT_OPC_S_AUTH_ACK is received
 */
bool xptClient_processPacket_authResponse(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read error code field
	uint32 authErrorCode = xptPacketbuffer_readU32(cpb, &readError);
	if( readError )
		return false;
	// read reject reason / motd
	char rejectReason[512];
	xptPacketbuffer_readString(cpb, rejectReason, 512, &readError);
	rejectReason[511] = '\0';
	if( readError )
		return false;
	if( authErrorCode == 0 )
	{
		xptClient->clientState = XPT_CLIENT_STATE_LOGGED_IN;
		printf("xpt: Logged in with %s\n", xptClient->username);
		if( rejectReason[0] != '\0' )
			printf("Message from server: %s\n", rejectReason);
		// start ping mechanism
		xptClient->time_sendPing = (uint32)time(NULL) + 60; // first ping after one minute
	}
	else
	{
		// error logging in -> disconnect
		printf("xpt: Failed to log in with %s\n", xptClient->username);
		if( rejectReason[0] != '\0' )
			printf("Reason: %s\n", rejectReason);
		return false;
	}
	// get algorithm used by this worker
	xptClient->algorithm = ALGORITHM_RIECOIN;//xptPacketbuffer_readU8(cpb, &readError);
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_WORKDATA1 is received
 * This is the first version of xpt 'getwork'
 */
bool xptClient_processPacket_blockData1(xptClient_t* xptClient)
{
	// parse block data
	bool recvError = false;
	xptPacketbuffer_beginReadPacket(xptClient->recvBuffer);
	xptClient->hasWorkData = false;
	// add general block info
	xptClient->blockWorkInfo.version = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// version
	xptClient->blockWorkInfo.height = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// block height
	xptClient->blockWorkInfo.nBits = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// nBits
	xptClient->blockWorkInfo.nBitsShare = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);		// nBitsRecommended / nBitsShare
	xptClient->blockWorkInfo.nTime = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);			// nTimestamp
	xptPacketbuffer_readData(xptClient->recvBuffer, xptClient->blockWorkInfo.prevBlockHash, 32, &recvError);	// prevBlockHash
	uint32 payloadNum = xptPacketbuffer_readU32(xptClient->recvBuffer, &recvError);							// payload num
	if (recvError) {
		printf("xptClient_processPacket_blockData1(): Parse error\n");
		return false;
	}
	for (uint32 i=0;i<payloadNum;i++) {
		// read merkle root for each work data entry
		xptPacketbuffer_readData(xptClient->recvBuffer, xptClient->blockWorkInfo.merklePayload[i].blockHash, 32, &recvError);	// prevBlockHash
		xptPacketbuffer_readData(xptClient->recvBuffer, xptClient->blockWorkInfo.merklePayload[i].merkleRoot, 32, &recvError);		
	}
	if (recvError) {
		printf("xptClient_processPacket_blockData1(): Parse error 2\n");
		return false;
	}
	xptClient->hasWorkData = true;
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_SHARE_ACK is received
 */
bool xptClient_processPacket_shareAck(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read error code field
	uint32 shareErrorCode = xptPacketbuffer_readU32(cpb, &readError);
	if( readError )
		return false;
	// read reject reason
	char rejectReason[512];
	xptPacketbuffer_readString(cpb, rejectReason, 512, &readError);
	rejectReason[511] = '\0';
	float shareValue = xptPacketbuffer_readFloat(cpb, &readError);
	if( readError )
		return false;
	if( shareErrorCode == 0 )
	{
		time_t now = time(0);
		char* dt = ctime(&now);
		printf("Share accepted by server\n");
		//printf(" [ %d / %d val: %.6f] %s", valid_shares, total_shares, shareValue, dt);
		//primeStats.fShareValue += shareValue;
	}
	else
	{
		// share not accepted by server
		printf("Invalid share\n");
		if( rejectReason[0] != '\0' )
			printf("Reason: %s\n", rejectReason);
		totalRejectedShareCount++;
	}
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_MESSAGE is received
 */
bool xptClient_processPacket_message(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read type field (not used yet)
	uint32 messageType = xptPacketbuffer_readU8(cpb, &readError);
	if( readError )
		return false;
	// read message text (up to 1024 bytes)
	char messageText[1024];
	xptPacketbuffer_readString(cpb, messageText, 1024, &readError);
	messageText[1023] = '\0';
	if( readError )
		return false;
	printf("Server message: %s\n", messageText);
	return true;
}

/*
 * Called when a packet with the opcode XPT_OPC_S_PING is received
 */
bool xptClient_processPacket_ping(xptClient_t* xptClient)
{
	xptPacketbuffer_t* cpb = xptClient->recvBuffer;
	// read data from the packet
	xptPacketbuffer_beginReadPacket(cpb);
	// start parsing
	bool readError = false;
	// read timestamp
	uint64 timestamp = xptPacketbuffer_readU64(cpb, &readError);
	if( readError )
		return false;
	// get current high precision time and frequency
	LARGE_INTEGER hpc;
	LARGE_INTEGER hpcFreq;
	QueryPerformanceCounter(&hpc);
	QueryPerformanceFrequency(&hpcFreq);
	uint64 timestampNow = (uint64)hpc.QuadPart;
	// calculate time difference in ms
	uint64 timeDif = timestampNow - timestamp;
	timeDif *= 10000ULL;
	timeDif /= (uint64)hpcFreq.QuadPart;
	// update and calculate simple average
	xptClient->pingSum += timeDif;
	xptClient->pingCount++;
	double averagePing = (double)xptClient->pingSum / (double)xptClient->pingCount / 10.0;
	printf("Ping %d.%dms (Average %.1lf)\n", (sint32)(timeDif/10), (sint32)(timeDif%10), averagePing);
	return true;
}