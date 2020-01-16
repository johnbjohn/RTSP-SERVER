#ifndef RTSPSERVICE_H_
#define RTSPSERVICE_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "rtsputils.h"

#define RTP_DEFAULT_PORT 5004

void PrefsInit();
void RTP_port_pool_init(int port);
void EventLoop(int s32MainFd);
void delete_last_clients(RTSP_buffer **ppRtspList, int *conn_count);
int rtsp_server(RTSP_buffer *rtsp);
void UpdateSps(unsigned char *data,int len);
void UpdatePps(unsigned char *data,int len);

#ifdef __cplusplus
}
#endif

#endif


