#ifndef RTSP_SERVER_H_
#define RTSP_SERVER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>

#include "rtspservice.h"
#include "rtputils.h"
#include "rtsputils.h"
#include "ringfifo.h"
#include <imp/imp_system.h>
#include "imp/imp_encoder.h"


#include <imp/imp_common.h>
#include <imp/imp_audio.h>

enum RTSP_STREAM_TYPE {MAIN_STREAM_VIDEO,SUB_STREAM_VIDEO};
enum VIDEO_TYPE {H264_VIDEO_TYPE, H265_VIDEO_TYPE};
enum AUDIO_TYPE {PCM_LINEAR_AUDIO_TYPE, PCM_ALAW_AUDIO_TYPE,PCM_ULAW_AUDIO_TYPE};

void Set_Channel_RTSP(unsigned int channel);
unsigned int Get_Channel_RTSP();
int PutPCMDataToBuffer(unsigned char *pstStream,unsigned int length,unsigned int format_type);
int Send_Video_RTSP(unsigned char *pstStream,unsigned int length,unsigned int video_type,unsigned int stream_type);
int Set_RTSP_Basic_Authorization(char* username,char*password);
void RTSP_Server_DeInit();
int rtsp_server_init(void);

#ifdef __cplusplus
}
#endif

#endif


