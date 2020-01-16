#include "rtsp_server.h"


extern int g_s32Quit ;
extern int n;
extern int iput;
extern struct ringbuf ringfifo[NMAX];
pthread_t rtsp_thread;
int rtsp_on=0;
int rtsp_quit_flag=0;
int audio_flag=0;
unsigned int video_stream_type;
unsigned int audio_stream_type;
int authorization_flag=0;
char username_rtsp[100];
char password_rtsp[100];
unsigned int rtsp_channel=1;


/**************************************************************************************************
**
**
**
**************************************************************************************************/
void Set_Channel_RTSP(unsigned int channel)
{
	rtsp_channel=channel;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
unsigned int Get_Channel_RTSP()
{
	unsigned int channel_temp=0;
	channel_temp=rtsp_channel;
	return channel_temp ;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
	int Send_Video_RTSP(unsigned char *pstStream,unsigned int length,unsigned int video_type,unsigned int stream_type)
	{
		if(pstStream==NULL)
		{
			return -1;
		}
		if(ringfifo[iput].buffer==NULL)
		{
			return -1;
		}
		video_stream_type=video_type;
		if(n<NMAX)
		{
			memcpy(ringfifo[iput].buffer,pstStream,length); 			
			ringfifo[iput].size= length;
			if(stream_type==MAIN_STREAM_VIDEO)
			{
				ringfifo[iput].data_type=HIGH_VIDEO;
			}
			else if(stream_type==SUB_STREAM_VIDEO)
			{
				ringfifo[iput].data_type=SUB_STREAM;
			}
			iput = addring(iput);
			n++;
			//printf("**********************************************	length :%i	 iput :%i \n",length,iput);
		}
		 return 0;
	}
/**************************************************************************************************
**
**
**
**************************************************************************************************/

int PutPCMDataToBuffer(unsigned char *pstStream,unsigned int length,unsigned int audio_type)
{
	int len=0;
	
	if(pstStream==NULL)
	{
		return -1;
	}
	if(ringfifo[iput].buffer==NULL)
	{
		return -1;
	}
	audio_stream_type=audio_type;
	audio_flag=1;
	if(n<NMAX)
	{
		memcpy(ringfifo[iput].buffer,pstStream, length);
		ringfifo[iput].size= length;
		ringfifo[iput].data_type= AUDIO_FRAME;
		iput = addring(iput);
		n++;
	}
	 return 0;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int Set_RTSP_Basic_Authorization(char* username,char*password)
{
	if(username==NULL)
	{
		return -1;
	}
	if(password==NULL)
	{
		return -1;
	}
	strcpy(username_rtsp,username);
	strcpy(password_rtsp,password);
	authorization_flag=1;
	return 0;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/

void* rtsp_server_connect()
{
	int s32MainFd;
	printf("RTSP Debug : RTSP server START\n");
	PrefsInit();
	printf("RTSP Debug : listen for client connecting...\n");	
	signal(SIGPIPE, SIG_IGN);
	s32MainFd = tcp_listen(SERVER_RTSP_PORT_DEFAULT);
	printf("RTSP Debug : [%s : %d] s32MainFd : %i \n",__func__,__LINE__,s32MainFd);
	RTP_port_pool_init(RTP_DEFAULT_PORT);
	while (!g_s32Quit)
	{
		usleep(500);
		EventLoop(s32MainFd);
	}
	sleep(2);
	printf("RTSP Debug : The  RTSP Server quit!\n");

	return 0;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/

int rtsp_server_init()
{
	int ret;
	ret = pthread_create(&rtsp_thread, NULL, rtsp_server_connect,NULL);
	if(ret != 0) 
	{
		printf("RTSP Debug : RTSP Thread Create Fail\n");
		return -1;
	}

	pthread_detach(rtsp_thread);
	printf("RTSP Debug : Create rtsp_thread thread OK.\n");
	
	if (ScheduleInit() == ERR_FATAL)
	{
		printf("RTSP Debug : [%s : %d]\n",__func__,__LINE__);
		printf("RTSP Debug : Fatal: Can't start scheduler %s, %i \nServer is aborting.\n", __FILE__, __LINE__);
		return 0;
	}
	return 0;
}


/**************************************************************************************************
**
**
**
**************************************************************************************************/
void RTSP_Server_DeInit()
{	
	rtsp_quit_flag=1;
}


