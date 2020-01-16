#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>


#include "rtspservice.h"
#include "rtputils.h"
#include "rtsputils.h"


#ifdef __cplusplus
extern "C" {
#endif

//#define SAVE_NALU 1
typedef struct
{
	/**//* byte 0 */
	unsigned char u4CSrcLen:4;      /**//* expect 0 */
	unsigned char u1Externsion:1;   /**//* expect 1, see RTP_OP below */
	unsigned char u1Padding:1;      /**//* expect 0 */
	unsigned char u2Version:2;      /**//* expect 2 */
	/**//* byte 1 */
	unsigned char u7Payload:7;      /**//* RTP_PAYLOAD_RTSP */
	unsigned char u1Marker:1;       /**//* expect 1 */
	/**//* bytes 2, 3 */
	unsigned short u16SeqNum;
	/**//* bytes 4-7 */
	unsigned int u32TimeStamp;
	/**//* bytes 8-11 */
	unsigned long u32SSrc;          /**//* stream number is used here. */
} StRtpFixedHdr_UDP;

typedef struct
{
	/**//* byte 0 */
	unsigned char u8Magic;      /**//* expect 0 */
	/**//* byte 1 */
	unsigned char u8Channel;      /**//* expect 0 */	
	/**//* byte 2-3 */
	unsigned short u16length;      /**//* expect 0 */	
	/**//* byte 4*/
	unsigned char u4CSrcLen:4;      /**//* expect 0 */
	unsigned char u1Externsion:1;   /**//* expect 1, see RTP_OP below */
	unsigned char u1Padding:1;      /**//* expect 0 */
	unsigned char u2Version:2;      /**//* expect 2 */
	/**//* byte 5 */
	unsigned char u7Payload:7;      /**//* RTP_PAYLOAD_RTSP */
	unsigned char u1Marker:1;       /**//* expect 1 */
	/**//* bytes 6, 7 */
	unsigned short u16SeqNum;
	/**//* bytes 8-11 */
	unsigned int u32TimeStamp;
	/**//* bytes 12-15 */
	unsigned long u32SSrc;          /**//* stream number is used here. */
} StRtpFixedHdr_TCP;

typedef struct
{
    /**//* byte 0 */
	unsigned char u8Magic;      /**//* expect 0 */
	/**//* byte 1 */
	unsigned char u8Channel;      /**//* expect 0 */	
	/**//* byte 2-3 */
	unsigned short u16length;      /**//* expect 0 */	
	/**//* byte 4*/
	unsigned char u4CSrcLensrcrpt:5;      /**//* expect 0 */
	unsigned char u1Paddingsrcrpt:1;      /**//* expect 0 */
	unsigned char u2Versionsrcrpt:2;      /**//* expect 2 */
	/**//* byte 5 */
	unsigned char u8Payloadtypesrcrpt;      /**//* RTP_PAYLOAD_RTSP */
	/**//* byte 6-7 */
	unsigned short u16lengthsrcrpt;      /**//* RTP_PAYLOAD_RTSP */	
	/**//* byte 8-11 */
	unsigned long u32SSrcsrcrpt;
	/**//* byte 12-15 */
	unsigned int u32timestampmswsrcrpt;
	/**//* byte 16-19 */
	unsigned int u32timestamplswsrcrpt;
	/**//* byte 20-23 */
	unsigned int u32rtpTimeStampsrcrpt;
	/**//* byte 24-27 */
	unsigned int u32pktcntsrcrpt;
	/**//* byte 28-31 */
	unsigned int u32octetcntsrcrpt;
	/**//* byte 32 */
	unsigned char u4CSrcLensrcdesc:5;      /**//* expect 0 */
	unsigned char u1Paddingsrcdesc:1;      /**//* expect 0 */
	unsigned char u2Versionsrcdesc:2;      /**//* expect 2 */
	/**//* byte 33 */
	unsigned char u8Payloadtypesrcdesc;
	/**//* byte 34-35 */
	unsigned short u16lengthsrcdesc;
	/**//* byte 36-39 */
	unsigned long u32SSrcsrcdesc;          /**//* stream number is used here. */
	/**//* byte 40 */
	unsigned char u8cnamesrcdesc;
	/**//* byte 41 */
	unsigned char u8lengthsrcdesc;
	/**//* byte 42-47 */
	unsigned char u8textsrcdesc[6];
	/**//* byte 48 */
	unsigned char u8typesrcdesc;
} StRtcpPkt;


typedef struct
{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u2Nri:2;
	unsigned char u1F:1;
} StNaluHdr; /**/ /* 1 BYTES */

typedef struct
{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u2Nri:2;
	unsigned char u1F:1;
} StFuIndicator; /**/ /* 1 BYTES */

typedef struct
{
	//byte 0
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
} StH265Hdr; /**/ /* 1 BYTES */

typedef struct
{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u1R:1;
	unsigned char u1E:1;
	unsigned char u1S:1;
} StFuHdr; /**/ /* 1 BYTES */

typedef struct _tagStRtpHandle
{
	int                 s32Sock;
	struct sockaddr_in  stServAddr;
	unsigned short      u16SeqNum;
	unsigned short      u16SeqNum_audio;
	unsigned long long        u32TimeStampInc;
	unsigned int        u32TimeStampCurr;
	unsigned long long      u32CurrTime;
	unsigned long long      u32PrevTime;
	unsigned int        u32SSrc;
	StRtpFixedHdr_TCP       *pRtpFixedHdr_TCP;
	StRtpFixedHdr_UDP       *pRtpFixedHdr_UDP;	
	StRtcpPkt       *pStRtcpPkt;
	StNaluHdr           *pNaluHdr;
	StFuIndicator       *pFuInd;
	StFuHdr             *pFuHdr;
	StH265Hdr             *pH265Hdr;
	EmRtpPayload        emPayload;
	int 			RTP_CHANNEL;
	int 			RTCP_CHANNEL;
} StRtpObj, *HndRtp;

int transport_layer_flag=0;
unsigned int timestam_test;
int  ssrc_rtsp;
extern int main_fd;
extern unsigned int video_stream_type;
extern unsigned int audio_stream_type;

/**************************************************************************************************
**
**
**
**************************************************************************************************/
unsigned int RtpCreate_udp(unsigned int u32IP, int s32Port, EmRtpPayload emPayload)
{
	HndRtp hRtp = NULL;
	struct timeval stTimeval;
	struct ifreq stIfr;
	int s32Broadcast = 1;

	hRtp = (HndRtp)calloc(1, sizeof(StRtpObj));
	if(NULL == hRtp)
	{
		printf("RTSP Debug : Failed to create RTP handle\n");
		goto cleanup;
	}


	hRtp->s32Sock = -1;
	if((hRtp->s32Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		printf("RTSP Debug : Failed to create socket\n");
		goto cleanup;
	}

	if(0xFF000000 == (u32IP & 0xFF000000))
	{
		if(-1 == setsockopt(hRtp->s32Sock, SOL_SOCKET, SO_BROADCAST, (char *)&s32Broadcast, sizeof(s32Broadcast)))
		{
			printf("RTSP Debug : Failed to set socket\n");
			goto cleanup;
		}
	}
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 1;
	setsockopt(hRtp->s32Sock, SOL_SOCKET, SO_SNDTIMEO,&tv,sizeof(tv));

	struct timeval tv_recv;
	tv_recv.tv_sec = 1;
	tv_recv.tv_usec = 1;
	setsockopt(hRtp->s32Sock, SOL_SOCKET, SO_RCVTIMEO,&tv_recv,sizeof(tv_recv));

	hRtp->stServAddr.sin_family = AF_INET;
	hRtp->stServAddr.sin_port = htons(s32Port);
	hRtp->stServAddr.sin_addr.s_addr = u32IP;
	bzero(&(hRtp->stServAddr.sin_zero), 8);

	//初始化序号
	hRtp->u16SeqNum = 0;
	hRtp->u16SeqNum_audio = 0;
	//初始化时间戳
	hRtp->u32TimeStampInc = 0;
	hRtp->u32TimeStampCurr = 0;

	//获取当前时间
	if(gettimeofday(&stTimeval, NULL) == -1)
	{
		printf("RTSP Debug : Failed to get os time\n");
		goto cleanup;
	}

	hRtp->u32PrevTime = stTimeval.tv_sec * 1000 + stTimeval.tv_usec / 1000;

	hRtp->emPayload = emPayload;

	static int hjk_1=0;
	if(hjk_1==0)
	{
		srand(time(0));	      	// Initialization, should only be called once.
		hjk_1=1;
	}
	int random_value = rand(); 	 		// Returns a pseudo-random integer between 0 and RAND_MAX.
	hRtp->u32SSrc = htonl(random_value);
	ssrc_rtsp=htonl(hRtp->u32SSrc);
	printf("RTSP Debug : <><><><>success creat RTP<><><><>\n");

	return (unsigned int)hRtp;

	cleanup:
	if(hRtp)
	{
		if(hRtp->s32Sock >= 0)
		{
			close(hRtp->s32Sock);
		}
		free(hRtp);
		hRtp=NULL;	
	}

	return 0;
}



/**************************************************************************************************
**
**
**
**************************************************************************************************/
unsigned int RtpCreate_tcp(unsigned int u32IP,int s32Port,  int RTP_Channel,int RTCP_Channel, EmRtpPayload emPayload)
{
	HndRtp hRtp = NULL;
	struct timeval stTimeval;
	hRtp = (HndRtp)calloc(1, sizeof(StRtpObj));
	if(NULL == hRtp)
	{
		printf("RTSP Debug : Failed to create RTP handle\n");
		goto cleanup;
	}

	hRtp->s32Sock = main_fd;
	hRtp->RTCP_CHANNEL= RTCP_Channel;
	hRtp->RTP_CHANNEL= RTP_Channel;
	hRtp->stServAddr.sin_family = AF_INET;
	hRtp->stServAddr.sin_port = htons(s32Port);
	hRtp->stServAddr.sin_addr.s_addr = u32IP;
	bzero(&(hRtp->stServAddr.sin_zero), 8);

	//初始化序号
	hRtp->u16SeqNum = 0;
	hRtp->u16SeqNum_audio = 0;
	//初始化时间戳
	hRtp->u32TimeStampInc = 0;
	hRtp->u32TimeStampCurr = 0;

	//获取当前时间
	if(gettimeofday(&stTimeval, NULL) == -1)
	{
		printf("RTSP Debug : Failed to get os time\n");
		goto cleanup;
	}
	hRtp->u32PrevTime = stTimeval.tv_sec * 1000 + stTimeval.tv_usec / 1000;
	hRtp->emPayload = emPayload;
	static int hjk=0;
	if(hjk==0)
	{
		srand(time(0));	      	// Initialization, should only be called once.
		hjk=1;
	}
	int random_value = rand(); 	 		// Returns a pseudo-random integer between 0 and RAND_MAX.
	hRtp->u32SSrc = htonl(random_value);
	ssrc_rtsp=htonl(hRtp->u32SSrc);
	printf("RTSP Debug : <><><><>success creat RTP<><><><>\n");
	return (unsigned int)hRtp;
	cleanup:
	if(hRtp)
	{
		if(hRtp->s32Sock >= 0)
		{
			close(hRtp->s32Sock);
		}
		free(hRtp);
		hRtp=NULL;	
	}

	return 0;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
void RtpDelete(RTP_session* u32Rtp)
{
	if(u32Rtp->hndRtp)
	{
		if(u32Rtp->transport.type==RTP_rtp_avp)
		{
			if(u32Rtp->hndRtp->s32Sock >= 0)
			{
				close(u32Rtp->hndRtp->s32Sock);
			}
		}
		free(u32Rtp->hndRtp);
		u32Rtp->hndRtp = NULL;
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
static int SendNalu264_UDP(HndRtp hRtp, char *pNalBuf, int s32NalBufSize)
{
	char *pNaluPayload;
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	char *pNaluCurr;
	int s32NaluRemain;
	unsigned char u8NaluBytes;

	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_H264+ 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}

	hRtp->pRtpFixedHdr_UDP= (StRtpFixedHdr_UDP*)pSendBuf;
	hRtp->pRtpFixedHdr_UDP->u7Payload   = H264;
	hRtp->pRtpFixedHdr_UDP->u2Version   = 2;
	hRtp->pRtpFixedHdr_UDP->u1Marker    = 0;
	hRtp->pRtpFixedHdr_UDP->u32SSrc     = hRtp->u32SSrc;
	//计算时间戳
	hRtp->pRtpFixedHdr_UDP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr * (90000 / 1000));

	//保存nalu首byte
	u8NaluBytes = *pNalBuf;
	//设置未发送的Nalu数据指针位置
	pNaluCurr = pNalBuf + 1;
	//设置剩余的Nalu数据数量
	s32NaluRemain = s32NalBufSize - 1;

	//NALU包小于等于最大包长度，直接发送
	if(s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264)
	{
		hRtp->pRtpFixedHdr_UDP->u1Marker    = 1;
		hRtp->pRtpFixedHdr_UDP->u16SeqNum   = htons(hRtp->u16SeqNum ++);
		hRtp->pNaluHdr                  = (StNaluHdr *)(pSendBuf + 12);
		hRtp->pNaluHdr->u1F             = (u8NaluBytes & 0x80) >> 7;
		hRtp->pNaluHdr->u2Nri           = (u8NaluBytes & 0x60) >> 5;
		hRtp->pNaluHdr->u5Type          = u8NaluBytes & 0x1f;

		pNaluPayload = (pSendBuf + 13);
		memcpy(pNaluPayload, pNaluCurr, s32NaluRemain);

		s32Bytes = s32NaluRemain + 13;
		if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
		{
			s32Ret = -1;
		}

	}
	//NALU包大于最大包长度，分批发送
	else
	{
		//指定fu indicator位置
		hRtp->pFuInd            = (StFuIndicator *)(pSendBuf + 12);
		hRtp->pFuInd->u1F       = (u8NaluBytes & 0x80) >> 7;
		hRtp->pFuInd->u2Nri     = (u8NaluBytes & 0x60) >> 5;
		hRtp->pFuInd->u5Type    = 28;

		//指定fu header位置
		hRtp->pFuHdr            = (StFuHdr *)(pSendBuf + 13);
		hRtp->pFuHdr->u1R       = 0;
		hRtp->pFuHdr->u5Type    = u8NaluBytes & 0x1f;

		//指定payload位置
		pNaluPayload = (pSendBuf + 14);

		//当剩余Nalu数据多于0时分批发送nalu数据
		while(s32NaluRemain > 0)
		{
			/*配置fixed header*/
			//每个包序号增1
			hRtp->pRtpFixedHdr_UDP->u16SeqNum = htons(hRtp->u16SeqNum ++);
			hRtp->pRtpFixedHdr_UDP->u1Marker = (s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264) ? 1 : 0;
			/*配置fu header*/
			//最后一批数据则置1
			hRtp->pFuHdr->u1E       = (s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264) ? 1 : 0;
			//第一批数据则置1
			hRtp->pFuHdr->u1S       = (s32NaluRemain == (s32NalBufSize - 1)) ? 1 : 0;
			s32Bytes = (s32NaluRemain < MAX_RTP_PKT_LENGTH_H264) ? s32NaluRemain : MAX_RTP_PKT_LENGTH_H264;
			memcpy(pNaluPayload, pNaluCurr, s32Bytes);
			//发送本批次
			s32Bytes = s32Bytes + 14;
			if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
			{
				s32Ret = -1;
				break;
			}
			else
			{
				//指向下批数据
				pNaluCurr += MAX_RTP_PKT_LENGTH_H264;
				//计算剩余的nalu数据长度
				s32NaluRemain -= MAX_RTP_PKT_LENGTH_H264;
			}
		}
	}

	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;	
	}

	return s32Ret;
}

static int SendNalu264_TCP(HndRtp hRtp, char *pNalBuf, int s32NalBufSize)
{
	char *pNaluPayload;
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	char *pNaluCurr;
	
	int s32NaluRemain;
	unsigned char u8NaluBytes;
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_H264 + 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}

	hRtp->pRtpFixedHdr_TCP = (StRtpFixedHdr_TCP *)pSendBuf;
	hRtp->pRtpFixedHdr_TCP->u8Magic= 0x24;
	hRtp->pRtpFixedHdr_TCP->u8Channel= hRtp->RTP_CHANNEL;
	hRtp->pRtpFixedHdr_TCP->u7Payload   = H264;
	hRtp->pRtpFixedHdr_TCP->u2Version   = 2;
	hRtp->pRtpFixedHdr_TCP->u1Marker    = 0;
	hRtp->pRtpFixedHdr_TCP->u32SSrc     = hRtp->u32SSrc;
	//计算时间戳
	hRtp->pRtpFixedHdr_TCP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr* (90000 / 1000));

	//保存nalu首byte
	u8NaluBytes = *pNalBuf;
	//设置未发送的Nalu数据指针位置
	pNaluCurr = pNalBuf + 1;
	//设置剩余的Nalu数据数量
	s32NaluRemain = s32NalBufSize - 1;
	//NALU包小于等于最大包长度，直接发送
	if(s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264)
	{
		hRtp->pRtpFixedHdr_TCP->u1Marker    = 1;
		hRtp->pRtpFixedHdr_TCP->u16SeqNum   = htons(hRtp->u16SeqNum ++);
		hRtp->pNaluHdr                  = (StNaluHdr *)(pSendBuf + 16);
		hRtp->pNaluHdr->u1F             = (u8NaluBytes & 0x80) >> 7;
		hRtp->pNaluHdr->u2Nri           = (u8NaluBytes & 0x60) >> 5;
		hRtp->pNaluHdr->u5Type          = u8NaluBytes & 0x1f;
		pNaluPayload = (pSendBuf + 17);
		memcpy(pNaluPayload, pNaluCurr, s32NaluRemain);
		s32Bytes = s32NaluRemain + 17;
		hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
		if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
		{
			s32Ret = -1;
		}

	}
	//NALU包大于最大包长度，分批发送
	else
	{
		//指定fu indicator位置
		hRtp->pFuInd            = (StFuIndicator *)(pSendBuf + 16);
		hRtp->pFuInd->u1F       = (u8NaluBytes & 0x80) >> 7;
		hRtp->pFuInd->u2Nri     = (u8NaluBytes & 0x60) >> 5;
		hRtp->pFuInd->u5Type    = 28;

		//指定fu header位置
		hRtp->pFuHdr            = (StFuHdr *)(pSendBuf + 17);
		hRtp->pFuHdr->u1R       = 0;
		hRtp->pFuHdr->u5Type    = u8NaluBytes & 0x1f;

		//指定payload位置
		pNaluPayload = (pSendBuf + 18);

		//当剩余Nalu数据多于0时分批发送nalu数据
		while(s32NaluRemain > 0)
		{
			/*配置fixed header*/
			//每个包序号增1
			hRtp->pRtpFixedHdr_TCP->u16SeqNum = htons(hRtp->u16SeqNum ++);
			hRtp->pRtpFixedHdr_TCP->u1Marker = (s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264) ? 1 : 0;
			/*配置fu header*/
			//最后一批数据则置1
			hRtp->pFuHdr->u1E       = (s32NaluRemain <= MAX_RTP_PKT_LENGTH_H264) ? 1 : 0;
			//第一批数据则置1
			hRtp->pFuHdr->u1S       = (s32NaluRemain == (s32NalBufSize - 1)) ? 1 : 0;
			s32Bytes = (s32NaluRemain < MAX_RTP_PKT_LENGTH_H264) ? s32NaluRemain : MAX_RTP_PKT_LENGTH_H264;
			memcpy(pNaluPayload, pNaluCurr, s32Bytes);
			//发送本批次
			s32Bytes = s32Bytes + 18;
			hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
			if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
			{
				s32Ret = -1;
				break;
			}
			else
			{
				//指向下批数据
				pNaluCurr += MAX_RTP_PKT_LENGTH_H264;
				//计算剩余的nalu数据长度
				s32NaluRemain -= MAX_RTP_PKT_LENGTH_H264;
			}
		}
	}

	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;	
	}
	return s32Ret;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
static int SendNalu265_UDP(HndRtp hRtp, char *pNalBuf, int s32NalBufSize)
{
	char *pNaluPayload;
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	char *pNaluCurr;
	int s32NaluRemain;
	unsigned char u8NaluBytes;
	
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_H265+ 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}
	unsigned char nal_type = (pNalBuf[4] >> 1) & 0x3F;

	hRtp->pRtpFixedHdr_UDP= (StRtpFixedHdr_UDP*)pSendBuf;
	hRtp->pRtpFixedHdr_UDP->u7Payload   = H265;
	hRtp->pRtpFixedHdr_UDP->u2Version   = 2;
	hRtp->pRtpFixedHdr_UDP->u1Marker    = 0;
	hRtp->pRtpFixedHdr_UDP->u32SSrc     = hRtp->u32SSrc;
	//计算时间戳
	hRtp->pRtpFixedHdr_UDP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr * (90000 / 1000));

	//保存nalu首byte
	u8NaluBytes = *pNalBuf;
	//设置未发送的Nalu数据指针位置
	pNaluCurr = pNalBuf + 1;
	//设置剩余的Nalu数据数量
	s32NaluRemain = s32NalBufSize - 1;
	
	if(s32NaluRemain <= MAX_RTP_PKT_LENGTH_H265)
	{
		hRtp->pRtpFixedHdr_UDP->u1Marker    = 1;
		hRtp->pRtpFixedHdr_UDP->u16SeqNum   = htons(hRtp->u16SeqNum ++);
		hRtp->pNaluHdr                  = (StNaluHdr *)(pSendBuf + 12);
		hRtp->pNaluHdr->u1F             = (u8NaluBytes  & 0x80) >> 7;
		hRtp->pNaluHdr->u2Nri           = (u8NaluBytes  & 0x60) >> 5;
		hRtp->pNaluHdr->u5Type          = u8NaluBytes  & 0x1f;
		pNaluPayload = (pSendBuf + 13);
		memcpy(pNaluPayload, pNaluCurr, s32NaluRemain);
		s32Bytes = s32NaluRemain + 13;
		if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
		{
			s32Ret = -1;
		}

	}
	//NALU包大于最大包长度，分批发送
	else
	{
		hRtp->pH265Hdr            = (StH265Hdr*)(pSendBuf + 12);
		hRtp->pH265Hdr->byte1       = 49<<1;
		hRtp->pH265Hdr->byte2= 1;
		hRtp->pH265Hdr->byte3= nal_type;
		hRtp->pH265Hdr->byte3 |= 1<<7;

		//指定payload位置
		pNaluPayload = (pSendBuf + 15);

		//当剩余Nalu数据多于0时分批发送nalu数据
		while(s32NaluRemain > 20000)
		{
			/*配置fixed header*/
			//每个包序号增1
			hRtp->pRtpFixedHdr_UDP->u16SeqNum = htons(hRtp->u16SeqNum ++);
			hRtp->pRtpFixedHdr_UDP->u1Marker = (s32NaluRemain <= 20000) ? 1 : 0;
			s32Bytes = (s32NaluRemain < 20000) ? s32NaluRemain : 20000;
			memcpy(pNaluPayload, pNaluCurr, s32Bytes);
			//发送本批次
			s32Bytes = s32Bytes + 15;
			if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
			{
				s32Ret = -1;
				break;
			}
			else
			{
				//指向下批数据
				pNaluCurr += 20000;
				//计算剩余的nalu数据长度
				s32NaluRemain -= 20000;
				hRtp->pH265Hdr->byte3 &= ~(1 << 7);
				
			}
		}
		hRtp->pH265Hdr->byte3 |= 1 << 6;
		hRtp->pRtpFixedHdr_UDP->u16SeqNum = htons(hRtp->u16SeqNum ++);
		hRtp->pRtpFixedHdr_UDP->u1Marker = (s32NaluRemain <= 20000) ? 1 : 0;
		s32Bytes = (s32NaluRemain <= 20000) ? s32NaluRemain : 20000;
		memcpy(pNaluPayload, pNaluCurr, s32Bytes);
		s32Bytes = s32Bytes + 15;
		if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
		{
			s32Ret = -1;
		}
	}

	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;	
	}

	return s32Ret;
}


/**************************************************************************************************
**
**
**
**************************************************************************************************/

static int SendNalu265_TCP(HndRtp hRtp, char *pNalBuf, int s32NalBufSize)
{
	char *pNaluPayload;
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	char *pNaluCurr;
	//char nal_type;
	int s32NaluRemain;
	unsigned char u8NaluBytes;
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_H265+ 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}
	unsigned char nal_type = (pNalBuf[4] >> 1) & 0x3F;
	hRtp->pRtpFixedHdr_TCP = (StRtpFixedHdr_TCP *)pSendBuf;
	hRtp->pRtpFixedHdr_TCP->u8Magic= 0x24;
	hRtp->pRtpFixedHdr_TCP->u8Channel= hRtp->RTP_CHANNEL;
	hRtp->pRtpFixedHdr_TCP->u7Payload   = H265;
	hRtp->pRtpFixedHdr_TCP->u2Version   = 2;
	hRtp->pRtpFixedHdr_TCP->u1Marker    = 0;
	hRtp->pRtpFixedHdr_TCP->u32SSrc       = hRtp->u32SSrc;
	//计算时间戳
	hRtp->pRtpFixedHdr_TCP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr* (90000 / 1000));

	//保存nalu首byte
	u8NaluBytes = *pNalBuf;
	//设置未发送的Nalu数据指针位置
	pNaluCurr = pNalBuf ;
	//设置剩余的Nalu数据数量
	s32NaluRemain = s32NalBufSize - 1;
	//NALU包小于等于最大包长度，直接发送
	if(s32NaluRemain <= MAX_RTP_PKT_LENGTH_H265)
	{
		hRtp->pRtpFixedHdr_TCP->u1Marker    = 1;
		hRtp->pRtpFixedHdr_TCP->u16SeqNum   = htons(hRtp->u16SeqNum ++);
		hRtp->pNaluHdr                  = (StNaluHdr *)(pSendBuf + 16);
		hRtp->pNaluHdr->u1F             = (u8NaluBytes  & 0x80) >> 7;
		hRtp->pNaluHdr->u2Nri           = (u8NaluBytes  & 0x60) >> 5;
		hRtp->pNaluHdr->u5Type          = u8NaluBytes  & 0x1f;
		pNaluPayload = (pSendBuf + 17);
		memcpy(pNaluPayload, pNaluCurr, s32NaluRemain);
		s32Bytes = s32NaluRemain + 17;
		hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
		if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
		{
			s32Ret = -1;
		}

	}
	//NALU包大于最大包长度，分批发送
	else
	{
		hRtp->pH265Hdr            = (StH265Hdr*)(pSendBuf + 16);
		hRtp->pH265Hdr->byte1       = 49<<1;
		hRtp->pH265Hdr->byte2= 1;
		hRtp->pH265Hdr->byte3= nal_type;
		hRtp->pH265Hdr->byte3 |= 1<<7;

		//指定payload位置
		pNaluPayload = (pSendBuf + 19);

		//当剩余Nalu数据多于0时分批发送nalu数据
		while(s32NaluRemain > 20000)
		{
			/*配置fixed header*/
			//每个包序号增1
			hRtp->pRtpFixedHdr_TCP->u16SeqNum = htons(hRtp->u16SeqNum ++);
			hRtp->pRtpFixedHdr_TCP->u1Marker = (s32NaluRemain <= 20000) ? 1 : 0;
			s32Bytes = (s32NaluRemain < 20000) ? s32NaluRemain : 20000;
			memcpy(pNaluPayload, pNaluCurr, s32Bytes);
			//发送本批次
			s32Bytes = s32Bytes + 19;
			hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
			if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
			{
				s32Ret = -1;
				break;
			}
			else
			{
				//指向下批数据
				pNaluCurr += 20000;
				//计算剩余的nalu数据长度
				s32NaluRemain -= 20000;
				hRtp->pH265Hdr->byte3 &= ~(1 << 7);
				
			}
		}
		hRtp->pH265Hdr->byte3 |= 1 << 6;
		hRtp->pRtpFixedHdr_TCP->u16SeqNum = htons(hRtp->u16SeqNum ++);
		hRtp->pRtpFixedHdr_TCP->u1Marker = (s32NaluRemain <= 20000) ? 1 : 0;
		s32Bytes = (s32NaluRemain <= 20000) ? s32NaluRemain : 20000;
		memcpy(pNaluPayload, pNaluCurr, s32Bytes);
		s32Bytes = s32Bytes + 19;
		hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
		if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
		{
			s32Ret = -1;
		}
	}

	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;	
	}
	return s32Ret;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/

static int SendRTCPPkt(HndRtp hRtp)
{
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_H264+ 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		s32Ret = -1;
		goto cleanup;
	}

	hRtp->pStRtcpPkt = (StRtcpPkt *)pSendBuf;
	hRtp->pStRtcpPkt->u8Magic= 0x24;
	hRtp->pStRtcpPkt->u8Channel= 1;
	hRtp->pStRtcpPkt->u8Payloadtypesrcrpt   = SOURCE_REPT;
	hRtp->pStRtcpPkt->u16lengthsrcrpt=htons(6);
	hRtp->pStRtcpPkt->u32rtpTimeStampsrcrpt = htonl(hRtp->u32TimeStampCurr );
	hRtp->pStRtcpPkt->u2Versionsrcrpt   = 2;
	hRtp->pStRtcpPkt->u1Paddingsrcrpt=0;
	hRtp->pStRtcpPkt->u4CSrcLensrcrpt=0;
	hRtp->pStRtcpPkt->u32SSrcsrcrpt     = hRtp->u32SSrc;
	hRtp->pStRtcpPkt->u32pktcntsrcrpt     = 0;
	hRtp->pStRtcpPkt->u32octetcntsrcrpt     = 0;
	hRtp->pStRtcpPkt->u2Versionsrcdesc  = 2;
	hRtp->pStRtcpPkt->u1Paddingsrcdesc=0;
	hRtp->pStRtcpPkt->u4CSrcLensrcdesc=1;
	hRtp->pStRtcpPkt->u8Payloadtypesrcdesc   = SOURCE_DESC;
	hRtp->pStRtcpPkt->u16lengthsrcdesc=htons(4);
	hRtp->pStRtcpPkt->u8cnamesrcdesc=1;
	hRtp->pStRtcpPkt->u8lengthsrcdesc=6;
	strncpy(hRtp->pStRtcpPkt->u8textsrcdesc,"Jhon-RnD",6);
	hRtp->pStRtcpPkt->u8typesrcdesc=0;
	hRtp->pStRtcpPkt->u32SSrcsrcdesc     = hRtp->u32SSrc;	
	hRtp->pStRtcpPkt->u16length=htons(48);
	s32Bytes=52;
	if(transport_layer_flag==0)
	{
		if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
		{
			s32Ret = -1;
			goto cleanup;
		}
	}
	else if(transport_layer_flag==1)
	{
		if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
		{
			s32Ret = -1;
			goto cleanup;
		}
	}
	cleanup:
	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;		
	}

	return s32Ret;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
static int SendNalu711_UDP(HndRtp hRtp, char *buf, int bufsize)
{
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_AUDIO + 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}
	hRtp->pRtpFixedHdr_UDP = (StRtpFixedHdr_UDP *)pSendBuf;
        if(audio_stream_type==PCM_LINEAR_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_UDP->u7Payload	  = G711;
	else if(audio_stream_type==PCM_ALAW_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_UDP->u7Payload	  = G711_PCMA;
	else if(audio_stream_type==PCM_ULAW_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_UDP->u7Payload	  = G711_PCMU;
	
	hRtp->pRtpFixedHdr_UDP->u2Version     = 2;
	hRtp->pRtpFixedHdr_UDP->u1Marker = 1;   //标志位，由具体协议规定其值。
	hRtp->pRtpFixedHdr_UDP->u32SSrc = hRtp->u32SSrc;
	hRtp->pRtpFixedHdr_UDP->u16SeqNum  = htons(hRtp->u16SeqNum_audio ++);
	memcpy(pSendBuf + 12, buf, bufsize);
	hRtp->pRtpFixedHdr_UDP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr* (8000 / 900));
	s32Bytes = bufsize + 12;
	if(sendto(hRtp->s32Sock, pSendBuf, s32Bytes, 0, (struct sockaddr *)&hRtp->stServAddr, sizeof(hRtp->stServAddr)) < 0)
	{
		printf("RTSP Debug : Failed to send!");
		s32Ret = -1;
	}
	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;		
	}
	return s32Ret;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
static int SendNalu711_TCP(HndRtp hRtp, char *buf, int bufsize)
{
	char *pSendBuf;
	int s32Bytes = 0;
	int s32Ret = 0;
	pSendBuf = (char *)calloc(MAX_RTP_PKT_LENGTH_AUDIO + 100, sizeof(char));
	if(NULL == pSendBuf)
	{
		return -1;
	}
	hRtp->pRtpFixedHdr_TCP = (StRtpFixedHdr_TCP *)pSendBuf;
	hRtp->pRtpFixedHdr_TCP->u8Magic= 0x24;
	hRtp->pRtpFixedHdr_TCP->u8Channel= hRtp->RTP_CHANNEL;
	if(audio_stream_type==PCM_LINEAR_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_TCP->u7Payload	  = G711;
	else if(audio_stream_type==PCM_ALAW_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_TCP->u7Payload	  = G711_PCMA;
	else if(audio_stream_type==PCM_ULAW_AUDIO_TYPE)
	hRtp->pRtpFixedHdr_TCP->u7Payload	  = G711_PCMU;
	
	hRtp->pRtpFixedHdr_TCP->u2Version   = 2;
	hRtp->pRtpFixedHdr_TCP->u1Marker    = 1;
	hRtp->pRtpFixedHdr_TCP->u32SSrc	   = hRtp->u32SSrc;
	hRtp->pRtpFixedHdr_TCP->u32TimeStamp = htonl(hRtp->u32TimeStampCurr* (8000 / 900));
	hRtp->pRtpFixedHdr_TCP->u16SeqNum  = htons(hRtp->u16SeqNum_audio++);
	memcpy(pSendBuf + 16, buf, bufsize);
	s32Bytes = bufsize + 16;
	hRtp->pRtpFixedHdr_TCP->u16length=htons(s32Bytes-4);
	if(tcp_write(hRtp->s32Sock,pSendBuf,s32Bytes)<0)
	{
		s32Ret = -1;
	}
	if(pSendBuf)
	{
		free((void *)pSendBuf);
		pSendBuf=NULL;		
	}
	return s32Ret;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/

unsigned int RtpSend_TCP(unsigned int u32Rtp, char *pData, int s32DataSize, unsigned int u32TimeStamp)
{
	int s32NalSize = 0;
	char *pNalBuf, *pDataEnd;
	HndRtp hRtp = (HndRtp)u32Rtp;
	unsigned int u32NaluToken;
	hRtp->u32TimeStampCurr = u32TimeStamp;
	
	if(_h264nalu == hRtp->emPayload)
	{
		if(SendNalu264_TCP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else if(_h265nalu == hRtp->emPayload)
	{
		if(SendNalu265_TCP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else if(_g711 == hRtp->emPayload)
	{
		if(SendNalu711_TCP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	return 0;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/

unsigned int RtpSend_UDP(unsigned int u32Rtp, char *pData, int s32DataSize, unsigned int u32TimeStamp)
{
	int s32NalSize = 0;
	char *pNalBuf, *pDataEnd;
	HndRtp hRtp = (HndRtp)u32Rtp;
	unsigned int u32NaluToken;
	hRtp->u32TimeStampCurr = u32TimeStamp;
	if(_h264nalu == hRtp->emPayload)
	{
		if(SendNalu264_UDP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else if(_h265nalu == hRtp->emPayload)
	{
		if(SendNalu265_UDP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else if(_g711 == hRtp->emPayload)
	{
		if(SendNalu711_UDP(hRtp, pData, s32DataSize) == -1)
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
	return 0;
}

#ifdef __cplusplus
}
#endif
