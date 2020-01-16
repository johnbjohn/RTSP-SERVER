#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/time.h>
#include "fcntl.h"

#include "rtspservice.h"
#include "rtsputils.h"
#include "rtputils.h"
#include "ringfifo.h"

extern int g_s32DoPlay;
extern int g_s32Quit ;
extern unsigned int video_stream_type;
extern unsigned int audio_stream_type;
extern int audio_flag;
extern int network_issue_flag;

char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen, char *str, size_t len)
{
	switch(sa->sa_family)
	{
		case AF_INET:
		{
			struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

			if(inet_ntop(AF_INET, &sin->sin_addr, str, len) == NULL)
			return(NULL);
			return(str);
		}
		default:
		snprintf(str, len, "sock_ntop_host: unknown AF_xxx: %d, len %d",
		sa->sa_family, salen);
		return(str);
	}
	return (NULL);
}

int tcp_accept(int fd)
{
	int f;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	memset(&addr,0,sizeof(addr));
	addrlen=sizeof(addr);

	/*接收连接，创建一个新的socket,返回其描述符*/
	f = accept(fd, (struct sockaddr *)&addr, &addrlen);

	return f;
}

void tcp_close(int s)
{
	close(s);
}

int tcp_connect(unsigned short port, char *addr)
{
	int f;
	int on=1;
	int one = 1;/*used to set SO_KEEPALIVE*/

	struct sockaddr_in s;
	int v = 1;
	if((f = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
	{
		 printf( "RTSP Debug : socket() error in tcp_connect.\n");
		return -1;
	}
	setsockopt(f, SOL_SOCKET, SO_REUSEADDR, (char *) &v, sizeof(int));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(addr);//htonl(addr);
	s.sin_port = htons(port);
	// set to non-blocking
	if(ioctl(f, FIONBIO, &on) < 0)
	{
		 printf("RTSP Debug : ioctl() error in tcp_connect.\n");
		return -1;
	}
	if(connect(f,(struct sockaddr*)&s, sizeof(s)) < 0)
	{
		 printf("RTSP Debug : connect() error in tcp_connect.\n");
		return -1;
	}
	if(setsockopt(f, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one))<0)
	{
		 printf("RTSP Debug : setsockopt() SO_KEEPALIVE error in tcp_connect.\n");
		return -1;
	}
	return f;
}

int tcp_listen(unsigned short port)
{
	int f;
	int on=1;

	struct sockaddr_in s;
	int v = 1;

	/*创建套接字*/
	if((f = socket(AF_INET, SOCK_STREAM, 0))<0)
	{
		 printf("RTSP Debug : socket() error in tcp_listen.\n");
		return -1;
	}

	/*设置socket的可选参数*/
	setsockopt(f, SOL_SOCKET, SO_REUSEADDR, (char *) &v, sizeof(int));


	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 1;
	setsockopt(f, SOL_SOCKET, SO_SNDTIMEO,&tv,sizeof(tv));

	struct timeval tv_recv;
	tv_recv.tv_sec = 1;
	tv_recv.tv_usec = 1;
	setsockopt(f, SOL_SOCKET, SO_RCVTIMEO,&tv_recv,sizeof(tv_recv));
		
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = htonl(INADDR_ANY);
	s.sin_port = htons(port);

	/*绑定socket*/
	if(bind(f, (struct sockaddr *)&s, sizeof(s)))
	{
		 printf( "RTSP Debug : bind() error in tcp_listen");
		return -1;
	}

	//设置为非阻塞方式
	if(ioctl(f, FIONBIO, &on) < 0)
	{
		 printf( "RTSP Debug : ioctl() error in tcp_listen.\n");
		return -1;
	}

	/*监听*/
	if(listen(f, MAX_CONNECTION) < 0)
	{
		 printf( "RTSP Debug : listen() error in tcp_listen.\n");
		return -1;
	}
	return f;
}

int tcp_read(int fd, void *buffer, int nbytes, struct sockaddr *Addr)
{
	int n;
	socklen_t Addrlen = sizeof(struct sockaddr);
	n=recv(fd, buffer, nbytes, 0);
	if(n>0)
	{
		//获取对方IP信息
		if(getpeername(fd, Addr, &Addrlen) < 0)
		{
			 printf("RTSP Debug : error getperrname:%s %i\n", __FILE__, __LINE__);
		}
	}
	return n;
}


int tcp_write(int connectSocketId, char *dataBuf, int dataSize)
{
	int     actDataSize;
	
	actDataSize = send(connectSocketId, dataBuf, dataSize, 0);
	if(actDataSize<=0)
	{
		network_issue_flag=1;
		perror("error Data size : ");
		return -1;
		
	}
	return 0;
}


/*      schedule 相关     */
stScheList sched[MAX_CONNECTION];

int num_conn = 0;    /*连接个数*/

int ScheduleInit()
{
	int i;
	pthread_t rtsp_schedule_thread=0;
	/*初始化数据*/
	for(i=0; i<MAX_CONNECTION; ++i)
	{
		sched[i].rtp_session=NULL;
		sched[i].play_action=NULL;
		sched[i].valid=0;
		sched[i].BeginFrame=0;
	}
	/*创建处理主线程*/
	pthread_create(&rtsp_schedule_thread,NULL,schedule_do,NULL);
	pthread_detach(rtsp_schedule_thread);

	return 0;
}
extern int rtsp_on;

void *schedule_do(void *arg)
{
	int i=0;
	struct timeval now;
	unsigned int mnow;
	//struct timespec ts = {0,33333};
	int s32FindNal = 0;
	int ringbuflen=0;
	struct ringbuf ringinfo;
	//=====================
	//SET_THREAD_NAME("rtsp_schedule");
	printf("RTSP Debug : The pthread %s start\n", __FUNCTION__);

	do
	{
		if(rtsp_on==1)
		{
			//nanosleep(&ts, NULL);
			s32FindNal = 0;
			ringbuflen = ringget(&ringinfo);
			
			if(ringbuflen ==0)
			continue ;
			
			s32FindNal = 1;
			if(ringinfo.buffer!=NULL)
			{
				for(i=0; i<MAX_CONNECTION; ++i)
				{
					if(sched[i].valid)
					{
						if(!sched[i].rtp_session->pause)
						{
							//计算时间戳
							gettimeofday(&now,NULL);
							mnow = (now.tv_sec*1000 + now.tv_usec/1000);//毫秒
							if(ringinfo.data_type==HIGH_VIDEO)
							{
								if(sched[i].rtp_session->sub_stream==0)
								{
									if((sched[i].rtp_session->hndRtp)&&(s32FindNal))
									{
										if(ringinfo.frame_type ==FRAME_TYPE_I)
										sched[i].BeginFrame=1;
										sched[i].play_action((unsigned int)(sched[i].rtp_session->hndRtp), ringinfo.buffer, ringinfo.size, mnow);
									}
								}
							}
							else if(ringinfo.data_type==SUB_STREAM)
							{
							
								if(sched[i].rtp_session->sub_stream==1)
								{
								
									if((sched[i].rtp_session->hndRtp)&&(s32FindNal))
									{
										if(ringinfo.frame_type ==FRAME_TYPE_I)
										sched[i].BeginFrame=1;
										sched[i].play_action((unsigned int)(sched[i].rtp_session->hndRtp), ringinfo.buffer, ringinfo.size, mnow);
									}
								}
							}

							if(audio_flag==1)
							{
								if(ringinfo.data_type==AUDIO_FRAME)
								{
									if((sched[i].rtp_session_audio->hndRtp)&&(s32FindNal))
									{
										sched[i].BeginFrame=1;
										sched[i].play_action((unsigned int)(sched[i].rtp_session_audio->hndRtp), ringinfo.buffer, ringinfo.size, mnow);
									}
								}
							}
						}
					}
				}
			//============add================
			//===============================
			}
		}
	}
	while(!g_s32Quit);
	
	printf("RTSP Debug : The pthread %s end\n", __FUNCTION__);
	return ERR_NOERROR;
}


  
int schedule_add_audio(RTP_session *rtp_session,RTP_session *rtp_session_audio)
{
	int i;
	for(i=0; i<MAX_CONNECTION; ++i)
	{
		/*需是还没有被加入到调度队列中的会话*/
		if(!sched[i].valid)
		{
			sched[i].valid=1;
			sched[i].rtp_session=rtp_session;
			sched[i].rtp_session_audio=rtp_session_audio;	
			//设置播放动作
			if(rtp_session->transport.type==RTP_rtp_avp)
			{
				sched[i].play_action=RtpSend_UDP;
			}
			else if(rtp_session->transport.type==RTP_rtp_avp_tcp)
			{
				sched[i].play_action=RtpSend_TCP;
			}
			return i;
		}
	}
	return ERR_GENERIC;
}

int schedule_add(RTP_session *rtp_session)
{
	int i;
	for(i=0; i<MAX_CONNECTION; ++i)
	{
		if(!sched[i].valid)
		{
			sched[i].valid=1;
			sched[i].rtp_session=rtp_session;

			//设置播放动作
			if(rtp_session->transport.type==RTP_rtp_avp)
			{
				sched[i].play_action=RtpSend_UDP;
			}
			else if(rtp_session->transport.type==RTP_rtp_avp_tcp)
			{
				sched[i].play_action=RtpSend_TCP;
			}
			return i;
		}
	}
	return ERR_GENERIC;
}

int schedule_start(int id,stPlayArgs *args)
{
	sched[id].rtp_session->pause=0;
	sched[id].rtp_session->started=1;
	if(audio_flag==1)
	{
		sched[id].rtp_session_audio->pause=0;
		sched[id].rtp_session_audio->started=1;
	}
	g_s32DoPlay++;
	printf("RTSP Debug : [%s: %d] g_s32DoPlay : %i \n",__func__,__LINE__,g_s32DoPlay);
	return ERR_NOERROR;
}

void schedule_stop(int id)
{
//    RTCP_send_packet(sched[id].rtp_session,SR);
//    RTCP_send_packet(sched[id].rtp_session,BYE);
}

int schedule_remove(int id)
{

	sched[id].valid=0;
	sched[id].BeginFrame=0;
	return ERR_NOERROR;
}


//把需要发送的信息放入rtsp.out_buffer中
int bwrite(char *buffer, unsigned short len, RTSP_buffer * rtsp)
{
	/*检查是否有缓冲溢出*/
	if((rtsp->out_size + len) > (int) sizeof(rtsp->out_buffer))
	{
		 printf("RTSP Debug : bwrite(): not enough free space in out message buffer.\n");
		return ERR_ALLOC;
	}
	/*填充数据*/
	memcpy(&(rtsp->out_buffer[rtsp->out_size]), buffer, len);
	rtsp->out_buffer[rtsp->out_size + len] = '\0';
	rtsp->out_size += len;
	return ERR_NOERROR;
}

int send_reply(int err, char *addon, RTSP_buffer * rtsp)
{
	unsigned int len;
	char *b;
	int res;

	if(addon != NULL)
	{
		len = 256 + strlen(addon);
	}
	else
	{
		len = 256;
	}

	/*分配空间*/
	b = (char *) malloc(len);
	if(b == NULL)
	{
		 printf("RTSP Debug : send_reply(): memory allocation error.\n");
		return ERR_ALLOC;
	}
	memset(b, 0, sizeof(b));
	/*按照协议格式填充数据*/
	if(addon != NULL)
	{
		sprintf(b, "%s %d %s"RTSP_EL"Server: %s/%s"RTSP_EL"CSeq: %d"RTSP_EL"%s"RTSP_EL, RTSP_VER, err, get_stat(err), PACKAGE, VERSION, rtsp->rtsp_cseq,addon);
		strcat(b, RTSP_EL);
	}
	else
	{
		sprintf(b, "%s %d %s"RTSP_EL"Server: %s/%s"RTSP_EL"CSeq: %d"RTSP_EL, RTSP_VER, err, get_stat(err), PACKAGE, VERSION, rtsp->rtsp_cseq);
		strcat(b, RTSP_EL);
	}

	/*将数据写入到缓冲区中*/
	res = bwrite(b, (unsigned short) strlen(b), rtsp);
	//释放空间
	free(b);
	b=NULL;
	return res;
}


//由错误码返回错误信息
const char *get_stat(int err)
{
    struct
    {
        const char *token;
        int code;
    } status[] =
    {
        {
            "Continue", 100
        }, {
            "OK", 200
        }, {
            "Created", 201
        }, {
            "Accepted", 202
        }, {
            "Non-Authoritative Information", 203
        }, {
            "No Content", 204
        }, {
            "Reset Content", 205
        }, {
            "Partial Content", 206
        }, {
            "Multiple Choices", 300
        }, {
            "Moved Permanently", 301
        }, {
            "Moved Temporarily", 302
        }, {
            "Bad Request", 400
        }, {
            "Unauthorized", 401
        }, {
            "Payment Required", 402
        }, {
            "Forbidden", 403
        }, {
            "Not Found", 404
        }, {
            "Method Not Allowed", 405
        }, {
            "Not Acceptable", 406
        }, {
            "Proxy Authentication Required", 407
        }, {
            "Request Time-out", 408
        }, {
            "Conflict", 409
        }, {
            "Gone", 410
        }, {
            "Length Required", 411
        }, {
            "Precondition Failed", 412
        }, {
            "Request Entity Too Large", 413
        }, {
            "Request-URI Too Large", 414
        }, {
            "Unsupported Media Type", 415
        }, {
            "Bad Extension", 420
        }, {
            "Invalid Parameter", 450
        }, {
            "Parameter Not Understood", 451
        }, {
            "Conference Not Found", 452
        }, {
            "Not Enough Bandwidth", 453
        }, {
            "Session Not Found", 454
        }, {
            "Method Not Valid In This State", 455
        }, {
            "Header Field Not Valid for Resource", 456
        }, {
            "Invalid Range", 457
        }, {
            "Parameter Is Read-Only", 458
        }, {
            "Unsupported transport", 461
        }, {
            "Internal Server Error", 500
        }, {
            "Not Implemented", 501
        }, {
            "Bad Gateway", 502
        }, {
            "Service Unavailable", 503
        }, {
            "Gateway Time-out", 504
        }, {
            "RTSP Version Not Supported", 505
        }, {
            "Option not supported", 551
        }, {
            "Extended Error:", 911
        }, {
            NULL, -1
        }
    };

    int i;
    for(i = 0; status[i].code != err && status[i].code != -1; ++i);

    return status[i].token;
}
