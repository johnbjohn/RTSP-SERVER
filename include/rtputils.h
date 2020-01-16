#ifndef _RTPUTILS_H
#define _RTPUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rtsputils.h"
#include <sys/socket.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <rtsp_server.h>
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_RTP_PKT_LENGTH_H265     65521
#define MAX_RTP_PKT_LENGTH_H264     2000
#define MAX_RTP_PKT_LENGTH_AUDIO     2000

#define H264                    96
#define H265                    98

#define G711			   97
#define G711_PCMA          8
#define G711_PCMU          0
#define PCM_LINEAR       11
#define SOURCE_REPT	   200
#define SOURCE_DESC	   202



typedef enum
{
	_h264		= 0x100,
	_h264nalu,
	_h265nalu,
	_mjpeg,
	_g711		= 0x200,
	_pcm_Alaw,
	_pcm_Ulaw,
}EmRtpPayload;

enum RTSP_DATA_TYPE {AUDIO_FRAME,HIGH_VIDEO,SUB_STREAM};
enum H264_FRAME_TYPE {FRAME_TYPE_I, FRAME_TYPE_P, FRAME_TYPE_B};

unsigned int RtpCreate_udp(unsigned int u32IP, int s32Port, EmRtpPayload emPayload);
unsigned int RtpCreate_tcp(unsigned int u32IP,int s32Port,  int RTP_Channel,int RTCP_Channel, EmRtpPayload emPayload);
void RtpDelete(RTP_session* u32Rtp);
unsigned int RtpSend_TCP(unsigned int u32Rtp, char *pData, int s32DataSize, unsigned int u32TimeStamp);
unsigned int RtpSend_UDP(unsigned int u32Rtp, char *pData, int s32DataSize, unsigned int u32TimeStamp);


#ifdef __cplusplus
}
#endif

#endif /* _RTPUTILS_H */
