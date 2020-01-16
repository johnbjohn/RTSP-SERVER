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
#include <errno.h>
#include "rtsputils.h"
#include "rtspservice.h"
#include "rtputils.h"
#include "ringfifo.h"
#include "rtsp_server.h"
char  pass_rtsp[20];
char  user_rtsp[20];
extern int audio_flag;
extern unsigned int video_stream_type;
extern unsigned int audio_stream_type;
extern int authorization_flag;
extern char username_rtsp[100];
extern char password_rtsp[100];
extern unsigned int rtsp_channel;
int network_issue_flag=0;


struct profileid_sps_pps{
	char base64profileid[10];
	char base64sps[524];
	char base64pps[524];
};

pthread_mutex_t mut; 

#define SDP_EL "\r\n"
#define RTSP_RTP_AVP "RTP/AVP"


struct profileid_sps_pps psp; //存base64编码的profileid sps pps

StServPrefs stPrefs;
extern int num_conn;
int g_s32Maxfd = 0;//最大轮询id号
int g_s32DoPlay = 0;
int main_fd=0;

uint32_t s_u32StartPort=RTP_DEFAULT_PORT;
uint32_t s_uPortPool[MAX_CONNECTION];//RTP端口
int g_s32Quit = 0;//退出全局变量
extern int rtsp_on;
extern int rtsp_quit_flag;
void RTP_port_pool_init(int port);
int UpdateSpsOrPps(unsigned char *data,int frame_type,int len);
/**************************************************************************************************
**
**
**
**************************************************************************************************/

static char encoding_table_64dec[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table_64dec = NULL;
static int mod_table_64dec[] = {0, 2, 1};


static void build_decoding_table_64dec() {
 
	decoding_table_64dec = malloc(256);
	int i;
	for ( i = 0; i < 64; i++)
		decoding_table_64dec[(unsigned char) encoding_table_64dec[i]] = i;
}
 
static int base64_decode_64dec(const char *data,size_t input_length,char* output_data)
{
	int i=0,j=0,output_length=0;
	if (decoding_table_64dec == NULL) build_decoding_table_64dec();

	if (input_length % 4 != 0) return NULL;

	output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (output_length)--;
	if (data[input_length - 2] == '=') (output_length)--;
	
	for ( i = 0, j = 0; i < input_length;) 
	{
		uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table_64dec[data[i++]];
		uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table_64dec[data[i++]];
		uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table_64dec[data[i++]];
		uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table_64dec[data[i++]];

		uint32_t triple = (sextet_a << 3 * 6)
		+ (sextet_b << 2 * 6)
		+ (sextet_c << 1 * 6)
		+ (sextet_d << 0 * 6);

		if (j < output_length) output_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < output_length) output_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < output_length) output_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return output_length;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
void PrefsInit()
{
	int l;
	//设置服务器信息全局变量
	stPrefs.port = SERVER_RTSP_PORT_DEFAULT;

	gethostname(stPrefs.hostname,sizeof(stPrefs.hostname));
	l=strlen(stPrefs.hostname);
	if (getdomainname(stPrefs.hostname+l+1,sizeof(stPrefs.hostname)-l)!=0)
	{
		stPrefs.hostname[l]='.';
	}
	printf("RTSP Debug : hostname is: %s\n", stPrefs.hostname);
	printf("RTSP Debug : rtsp listening port is: %d\n", stPrefs.port);
	
	struct ifreq ifr;
	char *IPbuffer;
	int test_ip=0;
	char IP[100]={0};
	/*TO GET ITS OWN IP ADDRESS*/
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &ifr))
	{
		strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
		ioctl(sockfd, SIOCGIFADDR, &ifr);	
	}
	close(sockfd);
	IPbuffer = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	strcpy(IP,IPbuffer);
	
	printf("RTSP Debug : Input rtsp://%s:%s@%s:%d/cam/realmonitor?channel=%i&subtype=0 to play HD video\n",username_rtsp,password_rtsp,IP,stPrefs.port,rtsp_channel);
	printf("RTSP Debug : Input rtsp://%s:%s@%s:%d/cam/realmonitor?channel=%i&subtype=1 to play SD video\n",username_rtsp,password_rtsp,IP,stPrefs.port,rtsp_channel);

}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//为缓冲分配空间
void RTSP_initserver(RTSP_buffer *rtsp, int fd)
{
	rtsp->fd = fd;
	rtsp->session_list = (RTSP_session *) calloc(1, sizeof(RTSP_session));
	rtsp->session_list->session_id = -1;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//为RTP准备两个端口
int RTP_get_port_pair(port_pair *pair)
{
	int i;

	for (i=0; i<MAX_CONNECTION; ++i)
	{
		if (s_uPortPool[i]!=0)
		{
			pair->RTP=(s_uPortPool[i]-s_u32StartPort)*2+s_u32StartPort;
			pair->RTCP=pair->RTP+1;
			s_uPortPool[i]=0;
			return ERR_NOERROR;
		}
	}
	return ERR_GENERIC;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void AddClient(RTSP_buffer **ppRtspList, int fd)
{
	RTSP_buffer *pRtsp=NULL,*pRtspNew=NULL;
	int ret=0;
	//在链表头部插入第一个元素
	if (*ppRtspList==NULL)
	{
		ringmalloc(256*1024);
		rtsp_on=1;
		memset(user_rtsp,0,sizeof(user_rtsp));	
		memset(pass_rtsp,0,sizeof(pass_rtsp));
		if ( !(*ppRtspList=(RTSP_buffer*)calloc(1,sizeof(RTSP_buffer)) ) )
		{
			printf("RTSP Debug : alloc memory error %s,%i\n", __FILE__, __LINE__);
			return;	
		}
		pRtsp = *ppRtspList;
	}
	else
	{
		//向链表中插入新的元素
		for (pRtsp=*ppRtspList; pRtsp!=NULL; pRtsp=pRtsp->next)
		{
			pRtspNew=pRtsp;
		}
		/*在链表尾部插入*/
		if (pRtspNew!=NULL)
		{
			if ( !(pRtspNew->next=(RTSP_buffer *)calloc(1,sizeof(RTSP_buffer)) ) )
			{
				printf("RTSP Debug : error calloc %s,%i\n", __FILE__, __LINE__);
				return;
			}
			pRtsp=pRtspNew->next;
			pRtsp->next=NULL;
		}
	}

	//设置最大轮询id号
	if(g_s32Maxfd < fd)
	{
		g_s32Maxfd = fd;
	}

	/*初始化新添加的客户端*/
	
	RTSP_initserver(pRtsp,fd);
	printf("RTSP Debug : Incoming RTSP connection accepted on socket: %d\n",pRtsp->fd);

}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
/*根据缓冲区的内容，填充后边两个长度数据,检查缓冲区中消息的完整性
 * return -1 on ERROR
 * return RTSP_not_full (0) if a full RTSP message is NOT present in the in_buffer yet.
 * return RTSP_method_rcvd (1) if a full RTSP message is present in the in_buffer and is
 *                     ready to be handled.
 * return RTSP_interlvd_rcvd (2) if a complete RTP/RTCP interleaved packet is present.
 * terminate on really ugly cases.
 */
int RTSP_full_msg_rcvd(RTSP_buffer *rtsp, int *hdr_len, int *body_len)
{
    int eomh;    /* end of message header found */
	int mb;       /* message body exists */
    int tc;         /* terminator count */
    int ws;        /* white space */
    unsigned int ml;              /* total message length including any message body */
    int bl;                           /* message body length */
    char c;                         /* character */
    int control;
    char *p;

    /*是否存在交叉存取的二进制rtp/rtcp数据包，参考RFC2326-10.12*/
    if (rtsp->in_buffer[0] == '$')
    {
    	uint16_t *intlvd_len = (uint16_t *)&rtsp->in_buffer[2];   /*跳过通道标志符*/

        /*转化为主机字节序，因为长度是网络字节序*/
        if ( (bl = ntohs(*intlvd_len)) <= rtsp->in_size)
        {
            if (hdr_len)
                *hdr_len = 4;
            if (body_len)
                *body_len = bl;
            return RTSP_interlvd_rcvd;
        }
        else
        {
            /*缓冲区不能完全存放数据*/
            return RTSP_not_full;
        }

    }


    eomh = mb = ml = bl = 0;
    while (ml <= rtsp->in_size)
    {
        /* look for eol. */
        /*计算不包含回车、换行在内的所有字符数*/
        control = strcspn(&(rtsp->in_buffer[ml]), "\r\n");
        if(control > 0)
            ml += control;
        else
            return ERR_GENERIC;

        /* haven't received the entire message yet. */
        if (ml > rtsp->in_size)
            return RTSP_not_full;


        /* 处理终结符，判读是否是消息头的结束*/
        tc = ws = 0;
        while (!eomh && ((ml + tc + ws) < rtsp->in_size))
        {
            c = rtsp->in_buffer[ml + tc + ws];
            /*统计回车换行*/
            if (c == '\r' || c == '\n')
                tc++;
            else if ((tc < 3) && ((c == ' ') || (c == '\t')))
            {
                ws++;                 /*回车、换行之间的空格或者TAB，也是可以接受的 */
            }
            else
            {
            	break;
            }
        }

        /*
         *一对回车、换行符仅仅被统计为一个行终结符
         * 双行可以被接受，并将其认为是消息头的结束标识
         * 这与RFC2068中的描述一致，参考rfc2068 19.3
         *否则，对所有的HTTP/1.1兼容协议消息元素来说，
         *回车、换行被认为是合法的行终结符
         */

        /* must be the end of the message header */
        if ((tc > 2) || ((tc == 2) && (rtsp->in_buffer[ml] == rtsp->in_buffer[ml + 1])))
            eomh = 1;
        ml += tc + ws;

        if (eomh)
        {
            ml += bl;   /* 加入消息体长度 */
            if (ml <= rtsp->in_size)
            	break;  /* all done finding the end of the message. */
        }

        if (ml >= rtsp->in_size)
            return RTSP_not_full;   /* 还没有完全接收消息 */

        /*检查每一行的第一个记号，确定是否有消息体存在 */
        if (!mb)
        {
            /* content length token not yet encountered. */
            if (!strncmp(&(rtsp->in_buffer[ml]), HDR_CONTENTLENGTH, strlen(HDR_CONTENTLENGTH)))
            {
                mb = 1;                        /* 存在消息体. */
                ml += strlen(HDR_CONTENTLENGTH);

                /*跳过:和空格，找到长度字段*/
                while (ml < rtsp->in_size)
                {
                    c = rtsp->in_buffer[ml];
                    if ((c == ':') || (c == ' '))
                        ml++;
                    else
                        break;
                }
                //Content-Length:后面是消息体长度值
                if (sscanf(&(rtsp->in_buffer[ml]), "%d", &bl) != 1)
                {
                    printf("RTSP Debug : RTSP_full_msg_rcvd(): Invalid ContentLength encountered in message.\n");
                    return ERR_GENERIC;
                }
            }
        }
    }

    if (hdr_len)
        *hdr_len = ml - bl;

    if (body_len)
    {
    /*
     * go through any trailing nulls.  Some servers send null terminated strings
     * following the body part of the message.  It is probably not strictly
     * legal when the null byte is not included in the Content-Length count.
     * However, it is tolerated here.
     * 减去可能存在的\0，它没有被计算在Content-Length中
     */
        for (tc = rtsp->in_size - ml, p = &(rtsp->in_buffer[ml]); tc && (*p == '\0'); p++, bl++, tc--);
            *body_len = bl;
    }

    return RTSP_method_rcvd;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
/*
 * return	0 是客户端发送的请求
 *			1 是服务器返回的响应
 */
int RTSP_valid_response_msg(unsigned short *status, RTSP_buffer * rtsp)
{
    char ver[32], trash[15];
    unsigned int stat;
    unsigned int seq;
    int pcnt;                   /* parameter count */

    /* assuming "stat" may not be zero (probably faulty) */
    stat = 0;

    /*从消息中填充数据*/
    pcnt = sscanf(rtsp->in_buffer, " %31s %u %s %s %u\n%*255s ", ver, &stat, trash, trash, &seq);

    /* 通过起始字符，检查信息是客户端发送的请求还是服务器做出的响应*/
    /* C->S CMD rtsp://IP:port/suffix RTSP/1.0\r\n			|head
     * 		CSeq: 1 \r\n									|
     * 		Content_Length:**								|body
     * S->C RTSP/1.0 200 OK\r\n
     * 		CSeq: 1\r\n
     * 		Date:....
      */
    if (strncmp(ver, "RTSP/", 5))
        return 0;   /*不是响应消息，是客户端请求消息，返回*/

    /*确信至少存在版本、状态码、序列号*/
    if (pcnt < 3 || stat == 0)
        return 0;            /* 表示不是一个响应消息   */

    /*如果版本不兼容，在此处增加码来拒绝该消息*/

    /*检查回复消息中的序列号是否合法*/
    if (rtsp->rtsp_cseq != seq + 1)
    {
         printf("RTSP Debug : Invalid sequence number returned in response.\n");
        return ERR_GENERIC;    /*序列号错误，返回*/
    }

    *status = stat;
    return 1;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//返回请求方法类型，出错返回-1
int RTSP_validate_method(RTSP_buffer * pRtsp)
{
	char method[32], hdr[16];
	char object[256];
	char ver[32];
	unsigned int seq;
	int pcnt;   /* parameter count */
	int mid = ERR_GENERIC;
	char *p; //=======增加
	char trash[255];   //===增加
	*method = *object = '\0';
	seq = 0;
	
	if ( (pcnt = sscanf(pRtsp->in_buffer, " %31s %255s %31s\n%15s", method, object, ver, hdr)) != 4)
	{
		return ERR_GENERIC;
	}
	//===========加
	if ((p = strstr(pRtsp->in_buffer, "CSeq")) == NULL) 
	{
		return ERR_GENERIC;
	}
	else 
	{
		if(sscanf(p,"%254s %d",trash,&seq)!=2)
		{
			return ERR_GENERIC;
		}
	}
	//==========

	/*根据不同的方法，返回响应的方法ID*/
	if (strcmp(method, RTSP_METHOD_DESCRIBE) == 0) {
	mid = RTSP_ID_DESCRIBE;
	}
	if (strcmp(method, RTSP_METHOD_ANNOUNCE) == 0) {
	mid = RTSP_ID_ANNOUNCE;
	}
	if (strcmp(method, RTSP_METHOD_GET_PARAMETERS) == 0) {
	mid = RTSP_ID_GET_PARAMETERS;
	}
	if (strcmp(method, RTSP_METHOD_OPTIONS) == 0) {
	mid = RTSP_ID_OPTIONS;
	}
	if (strcmp(method, RTSP_METHOD_PAUSE) == 0) {
	mid = RTSP_ID_PAUSE;
	}
	if (strcmp(method, RTSP_METHOD_PLAY) == 0) {
	mid = RTSP_ID_PLAY;
	}
	if (strcmp(method, RTSP_METHOD_RECORD) == 0) {
	mid = RTSP_ID_RECORD;
	}
	if (strcmp(method, RTSP_METHOD_REDIRECT) == 0) {
	mid = RTSP_ID_REDIRECT;
	}
	if (strcmp(method, RTSP_METHOD_SETUP) == 0) {
	mid = RTSP_ID_SETUP;
	}
	if (strcmp(method, RTSP_METHOD_SET_PARAMETER) == 0) {
	mid = RTSP_ID_SET_PARAMETER;
	}
	if (strcmp(method, RTSP_METHOD_TEARDOWN) == 0) {
	mid = RTSP_ID_TEARDOWN;
	}

	/*设置当前方法的请求序列号*/
	pRtsp->rtsp_cseq = seq;
	return mid;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//解析URL中的port端口和文件名称
int ParseUrl(const char *pUrl, char *pServer, unsigned short *port, char *pFileName, size_t FileNameLen)
{
	int s32NoValUrl;
	int channel_no=0;
	int sub_stream_no=0;
	/*拷贝URL */
	char *pFull = (char *)calloc(1,strlen(pUrl) + 1);
	strcpy(pFull, pUrl);

	/*检查前缀是否正确*/
	if (strncmp(pFull, "rtsp://", 7) == 0)
	{
		char *pSuffix;

		//找到/ 它之后是文件名
		if((pSuffix = strchr(&pFull[7], '/')) != NULL)
		{
			char *pPort;
			char pSubPort[128];
			memset(pSubPort,0,sizeof(pSubPort));	
			//判断是否有端口
			pPort=strchr(&pFull[7], ':');
			if(pPort != NULL)
			{	
				strncpy(pServer,&pFull[7],pPort-pFull-7);
				strncpy(pSubPort, pPort+1, pSuffix-pPort-1);
				pSubPort[pSuffix-pPort-1] = '\0';
				*port =  atoi(pSubPort);
				char *channel;
				char *test_ch;
				char channel_url[100];
				memset(channel_url,0,sizeof(channel_url));	
				char channel_no_char[10];
				channel=strchr(pPort, '?');
				if(channel != NULL)
				{
					char *sub_stream;
					char sub_stream_url[100];
					memset(sub_stream_url,0,sizeof(channel_url));	
					char sub_stream_no_char[10];
					sub_stream=strchr(channel, '&');
					if(sub_stream != NULL)
					{
						strncpy(channel_url, channel+1, ((sub_stream-1)-channel));
						strcpy(sub_stream_url,sub_stream+1);
						test_ch=strchr(channel_url, '=');
						if(test_ch != NULL)
						{
							strcpy(channel_no_char,test_ch+1);
							channel_no=atoi(channel_no_char);
						}
						test_ch=strchr(sub_stream_url, '=');
						if(test_ch != NULL)
						{
							strcpy(sub_stream_no_char,test_ch+1);
							sub_stream_no=atoi(sub_stream_no_char);
						}
					}
					else
					{
						strcpy(channel_url, channel+1);
						test_ch=strchr(channel_url, '=');
						if(test_ch != NULL)
						{
							strcpy(channel_no_char,test_ch+1);
							channel_no=atoi(channel_no_char);
						}
					}
					if(channel_no!=rtsp_channel || sub_stream_no  >1)
						s32NoValUrl = 2;
					else
						s32NoValUrl = 0;
				}
				else
				{
					s32NoValUrl = 0;
				}

			}
			else
			{
				s32NoValUrl = 0;
				*port = SERVER_RTSP_PORT_DEFAULT;
			}
			pSuffix++;
			//跳过空格或者制表符
			while(*pSuffix == ' '||*pSuffix == '\t')
			{
				pSuffix++;
			}
			//拷贝文件名
			strcpy(pFileName, pSuffix);

		}
		else
		{
			*port = SERVER_RTSP_PORT_DEFAULT;
			*pFileName = '\0';
			s32NoValUrl = 1;
		}
	}
	else
	{
		*pFileName = '\0';
		s32NoValUrl = 1;
	}
	//释放空间
	free(pFull);
	pFull=NULL;	
	return s32NoValUrl;
}

int ParseUrl_setup(const char *pUrl, char *pServer, unsigned short *sub_stream_rtp)
{
	int s32NoValUrl;
	int sub_stream_no=0;
	/*拷贝URL */
	char *pFull = (char *)calloc(1,strlen(pUrl) + 1);
	strcpy(pFull, pUrl);
	//CPP_DBG_PRINT("pUrl: %s",pUrl);
	/*检查前缀是否正确*/
	if (strncmp(pFull, "rtsp://", 7) == 0)
	{
		char *sub_stream_ptr;
		char	 sub_stream_char[10];
		memset(sub_stream_char,0,10);
		if((sub_stream_ptr = strstr(pFull, "subtype")))
		{
			char *equal_ch;
			equal_ch=strchr(sub_stream_ptr, '=');
			if(equal_ch != NULL)
			{
				char *slash_ch;
				slash_ch=strchr(equal_ch, '/');
				if(slash_ch != NULL)
				{
					strncpy(sub_stream_char,equal_ch+1,((slash_ch-1)-equal_ch));
					sub_stream_no=atoi(sub_stream_char);
				}
			}
		}
		if(sub_stream_no>1)
		{
			s32NoValUrl = 2;
		}
		else
		{
			*sub_stream_rtp=sub_stream_no;
			s32NoValUrl = 0;
		}
	}
	else
	{
		s32NoValUrl = 1;
	}
	//释放空间
	free(pFull);
	pFull=NULL;	
	return s32NoValUrl;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
//把当前时间作为session号
char *GetSdpId(char *buffer)
{
	time_t t;
	buffer[0]='\0';
	t = time(NULL);
	sprintf(buffer,"%.0f",(float)t+2208988800U);    /*获得NPT时间*/
	return buffer;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void GetSdpDescr(RTSP_buffer * pRtsp, char *pDescr, char *s8Str)
{
	struct ifreq stIfr;
	char pSdpId[128];
	char rtp_port[5];
	strcpy(stIfr.ifr_name, "eth0");
	if(ioctl(pRtsp->fd, SIOCGIFADDR, &stIfr) < 0)
	{
		strcpy(stIfr.ifr_name, "wlan0");
		if(ioctl(pRtsp->fd, SIOCGIFADDR, &stIfr) < 0)
		{
			printf("RTSP Debug : Failed to get host eth0 or wlan0 ip\n");
		}
	}
	sock_ntop_host(&stIfr.ifr_addr, sizeof(struct sockaddr), s8Str, 128);
	GetSdpId(pSdpId);

	strcpy(pDescr, "v=0\r\n");	
	strcat(pDescr, "o=-");
	strcat(pDescr, pSdpId);
	strcat(pDescr," ");
	strcat(pDescr, pSdpId);
	strcat(pDescr," IN IP4 ");
	strcat(pDescr, s8Str);
	strcat(pDescr, "\r\n");
	strcat(pDescr, "s=Unnamed\r\n");
	strcat(pDescr, "i=N/A\r\n");
	strcat(pDescr, "c=");
	strcat(pDescr, "IN ");		/* Network type: Internet. */
	strcat(pDescr, "IP4 ");		/* Address type: IP4. */
	//strcat(pDescr, get_address());
	strcat(pDescr, inet_ntoa(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr));
	strcat(pDescr, "\r\n");
	strcat(pDescr, "t=0 0\r\n");	
	strcat(pDescr, "a=recvonly\r\n");
	/**** media specific ****/
	strcat(pDescr,"m=");
	strcat(pDescr,"video ");
	sprintf(rtp_port,"%d",s_u32StartPort);
	strcat(pDescr, rtp_port);
	if(video_stream_type==H264_VIDEO_TYPE)
	{
		printf("RTSP Debug : H264 describe\n");
		strcat(pDescr," RTP/AVP "); /* Use UDP */
		strcat(pDescr,"96\r\n");
		//strcat(pDescr, "\r\n");
		strcat(pDescr,"b=RR:0\r\n");
		/**** Dynamically defined payload ****/
		strcat(pDescr,"a=rtpmap:96");
		strcat(pDescr," ");	
		strcat(pDescr,"H264/90000");
		strcat(pDescr, "\r\n");
	}
	else if(video_stream_type==H265_VIDEO_TYPE)
	{
		printf("RTSP Debug : H265 describe\n");
		strcat(pDescr," RTP/AVP "); /* Use UDP */
		strcat(pDescr,"98\r\n");
		//strcat(pDescr, "\r\n");
		strcat(pDescr,"b=RR:0\r\n");
		/**** Dynamically defined payload ****/
		strcat(pDescr,"a=rtpmap:98");
		strcat(pDescr," ");	
		strcat(pDescr,"H265/90000");
		strcat(pDescr, "\r\n");
	}
	strcat(pDescr,"a=control:trackID=0");
	strcat(pDescr, "\r\n");
	strcat(pDescr, "a=recvonly");
	strcat(pDescr, "\r\n");
	if(audio_flag==1)
	{
		if(audio_stream_type==PCM_LINEAR_AUDIO_TYPE)
		{
			strcat(pDescr, "m=audio 0 RTP/AVP 97");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=control:trackID=1");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=rtpmap:97 L16/8000");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=recvonly");
			strcat(pDescr, "\r\n"); 	
		}
		else if(audio_stream_type==PCM_ALAW_AUDIO_TYPE)
		{
			strcat(pDescr, "m=audio 0 RTP/AVP 8");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=control:trackID=1");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=rtpmap:8 PCMA/8000");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=recvonly");
			strcat(pDescr, "\r\n");
		}
		else if(audio_stream_type==PCM_ULAW_AUDIO_TYPE)
		{
			strcat(pDescr, "m=audio 0 RTP/AVP 0");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=control:trackID=1");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=rtpmap:0 PCMU/8000");
			strcat(pDescr, "\r\n");
			strcat(pDescr, "a=recvonly");
			strcat(pDescr, "\r\n");
		}
	}

}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
/*添加时间戳*/
void add_time_stamp(char *b, int crlf)
{
	struct tm *t;
	time_t now;

	/*
	* concatenates a null terminated string with a
	* time stamp in the format of "Date: 23 Jan 1997 15:35:06 GMT"
	*/
	now = time(NULL);
	t = gmtime(&now);
	//输出时间格式：Date: Fri, 15 Jul 2011 09:23:26 GMT
	strftime(b + strlen(b), 38, "Date: %a, %d %b %Y %H:%M:%S GMT"RTSP_EL, t);

	//是否是消息结束，添加回车换行符
	if (crlf)
		strcat(b, "\r\n");	/* add a message header terminator (CRLF) */
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int SendDescribeReply(RTSP_buffer * rtsp, char *object, char *descr, char *s8Str)
{
	char *pMsgBuf;            /* 用于获取响应缓冲指针*/
	int s32MbLen;

	/* 分配空间，处理内部错误*/
	s32MbLen = 2048;
	pMsgBuf = (char *)malloc(s32MbLen);
	if (!pMsgBuf)
	{
		 printf("RTSP Debug : send_describe_reply(): unable to allocate memory\n");
		send_reply(500, 0, rtsp);    /* internal server error */
		if (pMsgBuf)
		{
			free(pMsgBuf);
			pMsgBuf=NULL;		
		}
		return ERR_ALLOC;
	}

	/*构造describe消息串*/
	sprintf(pMsgBuf, "%s %d %s"RTSP_EL"CSeq: %d"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER, 200, get_stat(200), rtsp->rtsp_cseq, PACKAGE, VERSION);
	add_time_stamp(pMsgBuf, 0);                 /*添加时间戳*/
	strcat(pMsgBuf, "Content-Type: application/sdp"RTSP_EL);   /*实体头，表示实体类型*/
	sprintf(pMsgBuf + strlen(pMsgBuf), "Content-Base: rtsp://%s/%s/"RTSP_EL, s8Str, object);
	sprintf(pMsgBuf + strlen(pMsgBuf), "Content-Length: %d"RTSP_EL, strlen(descr)); /*消息体的长度*/
	strcat(pMsgBuf, RTSP_EL);
	strcat(pMsgBuf, descr);    /*describe消息*/
	bwrite(pMsgBuf, (unsigned short) strlen(pMsgBuf), rtsp);

	free(pMsgBuf);
	pMsgBuf=NULL;	

	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//describe处理
int RTSP_describe(RTSP_buffer * pRtsp)
{
	char object[255], trash[255];
	char *p;
	unsigned short port;
	char s8Url[255];
	char s8Descr[MAX_DESCR_LENGTH];
	char server[128];
	char s8Str[128];
	if (!sscanf(pRtsp->in_buffer, " %*s %254s ", s8Url))
	{
		 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);                			/* bad request */
		printf("RTSP Debug : get URL error");
		return ERR_NOERROR;
	}

	switch (ParseUrl(s8Url, server, &port, object, sizeof(object)))
	{
		case 1: /*请求错误*/
			 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);
			return ERR_NOERROR;
			break;

		case -1: /*内部错误*/
			 printf("RTSP Debug : url error while parsing !\n");
			send_reply(500, 0, pRtsp);
			return ERR_NOERROR;
			break;

		case 2:
			 printf("RTSP Debug : channel or sub stream error !\n");
			send_reply(404, 0, pRtsp);
			return ERR_NOERROR;
			break;

		default:
			break;
	}

	/*取得序列号,并且必须有这个选项*/
	if ((p = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);  /* Bad Request */
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(p, "%254s %d", trash, &(pRtsp->rtsp_cseq)) != 2)
		{
			 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);   /*请求错误*/
			return ERR_NOERROR;
		}
	}
	
	//获取SDP内容
	GetSdpDescr(pRtsp, s8Descr, s8Str);
	SendDescribeReply(pRtsp, object, s8Descr, s8Str);
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
//发送options处理后的响应
int send_options_reply(RTSP_buffer * pRtsp, long cseq)
{
	char r[1024];
	sprintf(r, "%s %d %s"RTSP_EL"Server: %s/%s"RTSP_EL"CSeq: %ld"RTSP_EL, RTSP_VER, 200, get_stat(200), PACKAGE, VERSION, cseq);
	strcat(r, "Public: OPTIONS,DESCRIBE,SETUP,PLAY,PAUSE,TEARDOWN"RTSP_EL);
	strcat(r, RTSP_EL);
	bwrite(r, (unsigned short) strlen(r), pRtsp);
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int check_username_pass_64dec(char* input)
{
	int leng_64dec=strlen(input);
	char user_64dec[40];
	memset(user_64dec,0,40);
	char pass_64dec[40];
	memset(pass_64dec,0,40);
	int i=0;
	int position_64dec=0;
	for(i=0;i<leng_64dec;i++)
	{
		if(input[i]==':')
		{
			position_64dec=i;
			break;
		}
	}
	for(i=0;i<position_64dec;i++)
	{
		user_64dec[i]=input[i];
	}
	for(i=position_64dec+1;i<leng_64dec;i++)
	{
		pass_64dec[i-(position_64dec+1)]=input[i];
	}
	if((strcmp(user_64dec,username_rtsp)==0) && (strcmp(pass_64dec,password_rtsp)==0))
	{
		return 1;
	}
	else
	{
		return 0; 
	}
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
//options处理
int RTSP_options(RTSP_buffer * pRtsp)
{
	char *p;
	char trash[255];
	unsigned int cseq;

	if ((p = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);/* Bad Request */
		printf("RTSP Debug : serial num error");
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(p, "%254s %d", trash, &(pRtsp->rtsp_cseq)) != 2)
		{
			 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);/* Bad Request */
			printf("RTSP Debug : serial num 2 error");
			return ERR_NOERROR;
		}
	}
	cseq = pRtsp->rtsp_cseq;
	send_options_reply(pRtsp, cseq);
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
extern int  ssrc_rtsp;

int send_setup_reply(RTSP_buffer *pRtsp, RTSP_session *pSession, RTP_session *pRtpSes)
{
	char s8Str[1024];
	sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %ld"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER,\
	200, get_stat(200), (long int)pRtsp->rtsp_cseq, PACKAGE, VERSION);
	add_time_stamp(s8Str, 0);
	sprintf(s8Str + strlen(s8Str), "Session: %d"RTSP_EL"Transport: ", (pSession->session_id));

	switch (pRtpSes->transport.type)
	{
		case RTP_rtp_avp:
			if (pRtpSes->transport.u.udp.is_multicast)
			{
			//				sprintf(s8Str + strlen(s8Str), "RTP/AVP;multicast;ttl=%d;destination=%s;port=", (int)DEFAULT_TTL, descr->multicast);
			}
			else
			{
				sprintf(s8Str + strlen(s8Str), "RTP/AVP;unicast;client_port=%d-%d;destination=192.168.245.65;source=%s;server_port=", \
				pRtpSes->transport.u.udp.cli_ports.RTP, pRtpSes->transport.u.udp.cli_ports.RTCP,"192.168.245.96");
			}
			sprintf(s8Str + strlen(s8Str), "%d-%d"RTSP_EL, pRtpSes->transport.u.udp.ser_ports.RTP, pRtpSes->transport.u.udp.ser_ports.RTCP);
			break;

		case RTP_rtp_avp_tcp:
			sprintf(s8Str + strlen(s8Str), "RTP/AVP/TCP;unicast;interleaved=%d-%d;ssrc=%08x"RTSP_EL,pRtpSes->transport.u.tcp.interleaved.RTP, pRtpSes->transport.u.tcp.interleaved.RTCP,ssrc_rtsp);
			ssrc_rtsp=0;
			break;

		default:
		break;
	}

	strcat(s8Str, RTSP_EL);
	bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
extern int transport_layer_flag;

//RTP_session *rtp_s_test;

int RTSP_setup(RTSP_buffer * pRtsp)
{
	char s8TranStr[128], *s8Str;
	char *pStr;
	RTP_transport Transport;
	int s32SessionID=0;
	RTP_session *rtp_s;
	char server[128];
	char s8Url[255];
	RTP_session *rtp_s_audio;
	
	RTSP_session *rtsp_s;
	if ((s8Str = strstr(pRtsp->in_buffer, HDR_TRANSPORT)) == NULL)
	{
		send_reply(406, 0, pRtsp);     // Not Acceptable
		printf("RTSP Debug : not acceptable");
		return ERR_NOERROR;
	}
	//检查传输层子串是否正确
	if (sscanf(s8Str, "%*10s %255s", s8TranStr) != 1)
	{
		 printf("RTSP Debug : SETUP request malformed: Transport string is empty\n");
		send_reply(400, 0, pRtsp);       // Bad Request
		return ERR_NOERROR;
	}


	//如果需要增加一个会话
	if ( !pRtsp->session_list )
	{
		pRtsp->session_list = (RTSP_session *) calloc(1, sizeof(RTSP_session));
	}
	rtsp_s = pRtsp->session_list;
	if(audio_flag==1)
	{
		if (pRtsp->session_list->rtp_session == NULL)
		{
			pRtsp->session_list->rtp_session = (RTP_session *) calloc(1, sizeof(RTP_session));
			rtp_s = pRtsp->session_list->rtp_session;
		}
		else
		rtp_s = pRtsp->session_list->rtp_session;	

		if (pRtsp->session_list->rtp_session_audio == NULL)
		{
			pRtsp->session_list->rtp_session_audio = (RTP_session*) calloc(1, sizeof(RTP_session));
			rtp_s_audio = pRtsp->session_list->rtp_session_audio;
		}	
		else
		rtp_s_audio = pRtsp->session_list->rtp_session_audio;	
	}
	else
	{
		//建立一个新会话，插入到链表中
		if (pRtsp->session_list->rtp_session == NULL)
		{
			pRtsp->session_list->rtp_session = (RTP_session *) calloc(1, sizeof(RTP_session));
			rtp_s = pRtsp->session_list->rtp_session;
		}
	}

	rtp_s->pause = 1;

	if(audio_flag==1)
	rtp_s_audio->pause = 1;

	

	
	if (!sscanf(pRtsp->in_buffer, " %*s %254s ", s8Url))
		{
			 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);							/* bad request */
			return ERR_NOERROR;
		}
	
		/*验证URL */
		switch (ParseUrl_setup(s8Url, server, &(rtp_s->sub_stream)))
		{
			case 1: /*请求错误*/
				 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
				send_reply(400, 0, pRtsp);
				return ERR_NOERROR;
				break;
	
			case -1: /*内部错误*/
				 printf("RTSP Debug : url error while parsing !\n");
				send_reply(500, 0, pRtsp);
				return ERR_NOERROR;
				break;
	
			case 2:
				 printf("RTSP Debug : channel or sub stream error !\n");
				send_reply(404, 0, pRtsp);
				return ERR_NOERROR;
				break;
	
			default:
				break;
		}
	Transport.type = RTP_no_transport;
	if((pStr = strstr(s8TranStr, RTSP_RTP_AVP)))
	{
		//Transport: RTP/AVP
		pStr += strlen(RTSP_RTP_AVP);
		char test[10];
		memset(test,0,10);
		strncpy(test,pStr,4);
		if ( !*pStr || (*pStr == ';') || (*pStr == ' ') )
		{
			//单播
			if (strstr(s8TranStr, "unicast"))
			{
				//如果指定了客户端端口号，填充对应的两个端口号
				if( (pStr = strstr(s8TranStr, "client_port")) )
				{
					pStr = strstr(s8TranStr, "=");
					sscanf(pStr + 1, "%d", &(Transport.u.udp.cli_ports.RTP));
					pStr = strstr(s8TranStr, "-");
					sscanf(pStr + 1, "%d", &(Transport.u.udp.cli_ports.RTCP));
				}

				//服务器端口
				if (RTP_get_port_pair(&Transport.u.udp.ser_ports) != ERR_NOERROR)
				{
					 printf("RTSP Debug : Error %s,%d\n", __FILE__, __LINE__);
					send_reply(500, 0, pRtsp);/* Internal server error */
					return ERR_GENERIC;
				}
				//建立RTP套接字
				if(audio_flag==1)
				{
					if(pRtsp->session_list->audio_video==0)
					{
						rtp_s->hndRtp = NULL;
						if(video_stream_type==H264_VIDEO_TYPE)
						rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_udp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), Transport.u.udp.cli_ports.RTP, _h264nalu);
						else if(video_stream_type==H265_VIDEO_TYPE)
						rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_udp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), Transport.u.udp.cli_ports.RTP, _h265nalu);
					}	
					else if(pRtsp->session_list->audio_video==1)
					{
						rtp_s_audio->hndRtp = NULL;
						rtp_s_audio->hndRtp = (struct _tagStRtpHandle*)RtpCreate_udp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), Transport.u.udp.cli_ports.RTP, _g711);
					}
				}
				else
				{
					if(video_stream_type==H264_VIDEO_TYPE)
					rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_udp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), Transport.u.udp.cli_ports.RTP, _h264nalu);
					else if(video_stream_type==H265_VIDEO_TYPE)
					rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_udp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), Transport.u.udp.cli_ports.RTP, _h265nalu);
				}
				printf("RTSP Debug : <><><><>Creat RTP<><><><>\n");

				Transport.u.udp.is_multicast = 0;
			}
			else
			{
				printf("RTSP Debug : multicast not codeing\n");
				//multicast 多播处理....
			}
			Transport.type = RTP_rtp_avp;
			transport_layer_flag=0;
		}
		else if (strncmp(pStr, "/TCP", 4)==0)
		{
			if( (pStr = strstr(s8TranStr, "interleaved")) )
			{
				pStr = strstr(s8TranStr, "=");
				sscanf(pStr + 1, "%d", &(Transport.u.tcp.interleaved.RTP));
				if ((pStr = strstr(pStr, "-")))
					sscanf(pStr + 1, "%d", &(Transport.u.tcp.interleaved.RTCP));
				else
					Transport.u.tcp.interleaved.RTCP = Transport.u.tcp.interleaved.RTP + 1;
				
				main_fd=pRtsp->fd;

				
				if(audio_flag==1)
				{
					if(pRtsp->session_list->audio_video==0)
					{
						if(video_stream_type==H264_VIDEO_TYPE)
						rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_tcp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), pRtsp->stClientAddr.sin_port,Transport.u.tcp.interleaved.RTP,Transport.u.tcp.interleaved.RTCP, _h264nalu);
						else if(video_stream_type==H265_VIDEO_TYPE)
						rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_tcp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), pRtsp->stClientAddr.sin_port,Transport.u.tcp.interleaved.RTP,Transport.u.tcp.interleaved.RTCP, _h265nalu);
					}	
					else if(pRtsp->session_list->audio_video==1)
					{
						rtp_s_audio->hndRtp = (struct _tagStRtpHandle*)RtpCreate_tcp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), pRtsp->stClientAddr.sin_port,Transport.u.tcp.interleaved.RTP,Transport.u.tcp.interleaved.RTCP, _g711);
					}
				}
				else
				{
					if(video_stream_type==H264_VIDEO_TYPE)
					rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_tcp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), pRtsp->stClientAddr.sin_port,Transport.u.tcp.interleaved.RTP,Transport.u.tcp.interleaved.RTCP, _h264nalu);
					else if(video_stream_type==H265_VIDEO_TYPE)
					rtp_s->hndRtp = (struct _tagStRtpHandle*)RtpCreate_tcp((unsigned int)(((struct sockaddr_in *)(&pRtsp->stClientAddr))->sin_addr.s_addr), pRtsp->stClientAddr.sin_port,Transport.u.tcp.interleaved.RTP,Transport.u.tcp.interleaved.RTCP, _h265nalu);
				}
				
			}
			Transport.rtp_fd = pRtsp->fd;
			Transport.type = RTP_rtp_avp_tcp;
           		transport_layer_flag=1;
		}
	}
	if (Transport.type == RTP_no_transport)
	{
		 printf("RTSP Debug : Unsupported Transport,%s,%d\n", __FILE__, __LINE__);
		send_reply(461, 0, pRtsp);// Bad Request
		return ERR_NOERROR;
	}
	
	if(audio_flag==1)
	{
		if(pRtsp->session_list->audio_video==0)
		{
			memcpy(&rtp_s->transport, &Transport, sizeof(Transport));
		}	
		else if(pRtsp->session_list->audio_video==1)
		{
			memcpy(&rtp_s_audio->transport, &Transport, sizeof(Transport));
		}
	}
	else		
	{
		memcpy(&rtp_s->transport, &Transport, sizeof(Transport));
	}
	

	//如果有会话头，就有了一个控制集合
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%*s %d", &s32SessionID) != 1)
		{
			 printf("RTSP Debug : Error %s,%i\n", __FILE__, __LINE__);
			send_reply(454, 0, pRtsp); // Session Not Found
			return ERR_NOERROR;
		}
	}
	else
	{
		//产生一个非0的随机的会话序号
		struct timeval stNowTmp;
		gettimeofday(&stNowTmp, 0);
		srand((stNowTmp.tv_sec * 1000) + (stNowTmp.tv_usec / 1000));
		s32SessionID = 1 + (int) (10.0 * rand() / (100000 + 1.0));
		if (s32SessionID == 0)
		{
			s32SessionID++;
		}
	}

	pRtsp->session_list->session_id = s32SessionID;
	
	if(audio_flag==1)
	{
		if(pRtsp->session_list->audio_video==0)
		{
			pRtsp->session_list->audio_video=1;
			send_setup_reply(pRtsp, rtsp_s, rtp_s);
		}	
		else if(pRtsp->session_list->audio_video==1)
		{
			pRtsp->session_list->rtp_session->sched_id = schedule_add_audio(rtp_s,rtp_s_audio);
			send_setup_reply(pRtsp, rtsp_s, rtp_s_audio);
		}
	}
	else
	{
		pRtsp->session_list->rtp_session->sched_id = schedule_add(rtp_s);
		send_setup_reply(pRtsp, rtsp_s, rtp_s);
	}
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int send_play_reply(RTSP_buffer * pRtsp, RTSP_session * pRtspSessn)
{
	char s8Str[2056];
	char s8Temp[500];
	struct timeval now;
    	unsigned int mnow;

	memset(s8Temp,0,sizeof(s8Temp));			
	gettimeofday(&now,NULL);
        mnow = (now.tv_sec*1000 + now.tv_usec/1000);//毫秒
	sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %d"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER, 200,\
			get_stat(200), pRtsp->rtsp_cseq, PACKAGE, VERSION);
	add_time_stamp(s8Str, 0);

	sprintf(s8Temp, "Session: %d"RTSP_EL, pRtspSessn->session_id);
	strcat(s8Str, s8Temp);
	memset(s8Temp,0,sizeof(s8Temp));
	sprintf(s8Temp, "Range: npt%s"RTSP_EL, pRtspSessn->npt_range);
	strcat(s8Str, s8Temp);
	memset(s8Temp,0,sizeof(s8Temp));	
	sprintf(s8Temp, "RTP-Info: url=trackID=0;seq=0;rtptime=%u",(unsigned int)mnow* (90000 / 1000));
	strcat(s8Str, s8Temp);
	if(audio_flag==1)
	{
		memset(s8Temp,0,sizeof(s8Temp));
		sprintf(s8Temp, ",url=trackID=1;seq=0;rtptime=%u"RTSP_EL,(unsigned int)mnow* (8000 / 900));
		strcat(s8Str, s8Temp);
	}
	else
	{
		strcat(s8Str, RTSP_EL);
	}
	strcat(s8Str, RTSP_EL);
	
	bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int play_flag=0;
int RTSP_play(RTSP_buffer * pRtsp)
{
	char *pStr;
	char* pStrTime;
	char pTrash[128];
	long int s32SessionId;
	RTSP_session *pRtspSesn;
	RTP_session *pRtpSesn;

	//获取CSeq
	if ((pStr = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		send_reply(400, 0, pRtsp);   /* Bad Request */
		printf("RTSP Debug : get CSeq!!400");
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(pStr, "%254s %d", pTrash, &(pRtsp->rtsp_cseq)) != 2)
		{
			send_reply(400, 0, pRtsp);    /* Bad Request */
			printf("RTSP Debug : get CSeq!! 2 400");
			return ERR_NOERROR;
		}
	}

	//获取session
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%254s %ld", pTrash, &s32SessionId) != 2)
		{
			send_reply(454, 0, pRtsp);// Session Not Found
			printf("RTSP Debug : Session Not Found");
			return ERR_NOERROR;
		}
	}
	else
	{
		send_reply(400, 0, pRtsp);// bad request
		printf("RTSP Debug : Session Not Found bad request");
		return ERR_NOERROR;
	}

	//时间参数,假设都是 0-0,不做设置
	if ((pStr = strstr(pRtsp->in_buffer, HDR_RANGE)) != NULL)
	{
		if((pStrTime = strstr(pRtsp->in_buffer, "npt")) != NULL)
		{
			if((pStrTime = strstr(pStrTime, "=")) == NULL)
			{
				send_reply(400, 0, pRtsp);// Bad Request
				return ERR_NOERROR;
			}
                      // strncpy(pRtsp->session_list->npt_range,pStrTime,sizeof(pRtsp->session_list->npt_range));
                      sscanf(pStrTime,"%s %s",pRtsp->session_list->npt_range,pTrash);
		}
		else
		{

		}
	}

	//播放list指向的rtp session
	pRtspSesn = pRtsp->session_list;
	if (pRtspSesn != NULL)
	{
		if (pRtspSesn->session_id == s32SessionId)
		{
			//查找RTP session,播放list中所有的session，本例程只有一个成员.
			for (pRtpSesn = pRtspSesn->rtp_session; pRtpSesn != NULL; pRtpSesn = pRtpSesn->next)
			{
				//播放所有演示
				if (!pRtpSesn->started)
				{
					//开始新的播放
					printf("RTSP Debug : \t+++++++++++++++++++++\n");
					printf("RTSP Debug : \tstart to play %d now!\n", pRtpSesn->sched_id);
					printf("RTSP Debug : \t+++++++++++++++++++++\n");

					if (schedule_start(pRtpSesn->sched_id, NULL) == ERR_ALLOC)
					{
						return ERR_ALLOC;
					}
				}
			}
		}
		else
		{
			send_reply(454, 0, pRtsp);	// Session not found
			return ERR_NOERROR;
		}
	}
	else
	{
		send_reply(415, 0, pRtsp);  // Internal server error
		return ERR_GENERIC;
	}
        play_flag=1;
	send_play_reply(pRtsp, pRtspSesn);

	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int send_teardown_reply(RTSP_buffer * pRtsp, long SessionId, long cseq)
{
	char s8Str[1024];
	char s8Temp[30];

	// 构建回复消息
	sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %ld"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER,\
			200, get_stat(200), cseq, PACKAGE, VERSION);
	//添加时间戳
	add_time_stamp(s8Str, 0);
	//会话ID
	sprintf(s8Temp, "Session: %ld"RTSP_EL, SessionId);
	strcat(s8Str, s8Temp);

	strcat(s8Str, RTSP_EL);

	//写入缓冲区
	bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

	return ERR_NOERROR;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
//int teardown_flag=0;
int RTSP_teardown(RTSP_buffer * pRtsp)
{
	char *pStr;
	char pTrash[128];
	long int s32SessionId;
	RTSP_session *pRtspSesn;

	//获取CSeq
	if ((pStr = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		send_reply(400, 0, pRtsp);   // Bad Request
		printf("RTSP Debug : get CSeq error");
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(pStr, "%254s %d", pTrash, &(pRtsp->rtsp_cseq)) != 2)
		{
			send_reply(400, 0, pRtsp);    // Bad Request
			printf("RTSP Debug : get CSeq 2 error");
			return ERR_NOERROR;
		}
	}

	//获取session
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%254s %ld", pTrash, &s32SessionId) != 2)
		{
			send_reply(454, 0, pRtsp);	// Session Not Found
			return ERR_NOERROR;
		}
	}
	else
	{
		s32SessionId = -1;
	}

	pRtspSesn = pRtsp->session_list;
	if (pRtspSesn == NULL)
	{
		send_reply(415, 0, pRtsp);  // Internal server error
		return ERR_GENERIC;
	}

	if (pRtspSesn->session_id != s32SessionId)
	{
		send_reply(454, 0, pRtsp);	// Session not found
		return ERR_NOERROR;
	}
	//向客户端发送响应消息
	send_teardown_reply(pRtsp, s32SessionId, pRtsp->rtsp_cseq);
	//释放所有的URI RTP会话
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
/*rtsp状态机，服务器端*/
void RTSP_state_machine(RTSP_buffer * pRtspBuf, int method)
{
    char *s;
    RTSP_session *pRtspSess;
    long int session_id;
    char trash[255];
    char szDebug[255];

    /*找到会话位置*/
    if ((s = strstr(pRtspBuf->in_buffer, HDR_SESSION)) != NULL)
    {
        if (sscanf(s, "%254s %ld", trash, &session_id) != 2)
        {
             printf("RTSP Debug : Invalid Session number %s,%i\n", __FILE__, __LINE__);
            send_reply(454, 0, pRtspBuf);              /* 没有此会话*/
            return;
        }
    }

    /*打开会话列表*/
    pRtspSess = pRtspBuf->session_list;
    if (pRtspSess == NULL)
    {
        return;
    }
   if(authorization_flag==1)
   	{
		   if ((s = strstr(pRtspBuf->in_buffer, "Authorization:"))==NULL)
		   	  {
			   	  char add_string[256];
			   	  printf( "RTSP Debug : UNAUTHORIZED\n");
			   	  memset(add_string,0,256);
			   	  sprintf(add_string,"WWW-Authenticate: Basic realm=\"RtspServer2.0\"");
			   	  send_reply(401,add_string , pRtspBuf);// Bad Request 
			   	  return ;
		   	  }   
		   else
		         {
			   	   s = strstr(pRtspBuf->in_buffer, "Basic");
			   	  char base64_dec[100];
			   	  memset(base64_dec,0,100);
			   	  char user_pass[100];
			   	  memset(user_pass,0,100);
			   	   if (sscanf(s, "%254s %s", trash, base64_dec))
			   	  {
			   	  	//CPP_DBG_PRINT("base64_dec :%s\n",base64_dec);
			   		  base64_decode_64dec(base64_dec,strlen(base64_dec),user_pass);
					  //CPP_DBG_PRINT("user_pass :%s",user_pass);
			   		  if(check_username_pass_64dec(user_pass)==0)
			   		  {		
			   			  char add_string[256];
			  			  printf( "RTSP Debug : UNAUTHORIZED\n");
			   			  memset(add_string,0,256);
			   			  sprintf(add_string,"WWW-Authenticate: Basic realm=\"RtspServer2.0\"");
			   			  send_reply(401,add_string , pRtspBuf);// Bad Request 
			   			  return ;
			   		  }
			   	  }
		   	   
		        }
       }
    sprintf(szDebug,"state_machine:current state is  ");
    strcat(szDebug,((pRtspSess->cur_state==0)?"init state":((pRtspSess->cur_state==1)?"ready state":"play state")));
    printf("RTSP Debug : %s\n", szDebug);

    /*根据状态迁移规则，从当前状态开始迁移*/
    switch (pRtspSess->cur_state)
    {
        case INIT_STATE:                    /*初始态*/
        {
	    printf("RTSP Debug : current method code is:  %d  \n",method);
            switch (method)
            {
                case RTSP_ID_DESCRIBE:  //状态不变
                    RTSP_describe(pRtspBuf);
                    break;

                case RTSP_ID_SETUP:                //状态变为就绪态
                  if (RTSP_setup(pRtspBuf) == ERR_NOERROR)
                    {
                    	pRtspSess->cur_state = READY_STATE;
                         printf("RTSP Debug : TRANSFER TO READY STATE!\n");
                    }
                    break;

                case RTSP_ID_TEARDOWN:       //状态不变
                    RTSP_teardown(pRtspBuf);
                    break;

                case RTSP_ID_OPTIONS:
                    if (RTSP_options(pRtspBuf) == ERR_NOERROR)
                    {
                    	pRtspSess->cur_state = INIT_STATE;         //状态不变
                    }
                    break;

                case RTSP_ID_PLAY:          //method not valid this state.

                case RTSP_ID_PAUSE:
                    send_reply(455, 0, pRtspBuf);
                    break;

                default:
                    send_reply(501, 0, pRtspBuf);
                    break;
            }
        break;
        }

        case READY_STATE:
        {
             printf("RTSP Debug : current method code is:%d\n",method);

            switch (method)
            {
                case RTSP_ID_PLAY:                                      //状态迁移为播放态
                   if (RTSP_play(pRtspBuf) == ERR_NOERROR)
                    {
                         printf("RTSP Debug : \tStart Playing!\n");
                        pRtspSess->cur_state = PLAY_STATE;
                    }
                    break;

                case RTSP_ID_SETUP:
                    if (RTSP_setup(pRtspBuf) == ERR_NOERROR)    //状态不变
                    {
                        pRtspSess->cur_state = READY_STATE;
                    }
                    break;

                case RTSP_ID_TEARDOWN:
                    RTSP_teardown(pRtspBuf);                 //状态变为初始态 ?
                    break;

                case RTSP_ID_OPTIONS:
                    if (RTSP_options(pRtspBuf) == ERR_NOERROR)
                    {
                        pRtspSess->cur_state = INIT_STATE;          //状态不变
                    }
                    break;

                case RTSP_ID_PAUSE:         			// method not valid this state.
                    send_reply(455, 0, pRtspBuf);
                    break;

                case RTSP_ID_DESCRIBE:
                    RTSP_describe(pRtspBuf);
                    break;

                default:
                    send_reply(501, 0, pRtspBuf);
                    break;
            }

            break;
        }


        case PLAY_STATE:
        {
            switch (method)
            {
                case RTSP_ID_PLAY:
                    // Feature not supported
                     printf("RTSP Debug : UNSUPPORTED: Play while playing.\n");
		
                    send_reply(551, 0, pRtspBuf);        // Option not supported
                    break;

                case RTSP_ID_TEARDOWN:
                    RTSP_teardown(pRtspBuf);        //状态迁移为初始态
                    break;

                case RTSP_ID_OPTIONS:
		   RTSP_options(pRtspBuf) ;
                    break;

                case RTSP_ID_DESCRIBE:
                    RTSP_describe(pRtspBuf);
                    break;

                case RTSP_ID_SETUP:
                    break;
            }

            break;
        }/* PLAY state */

        default:
            {
                /* invalid/unexpected current state. */
                printf("RTSP Debug : %s State error: unknown state=%d, method code=%d\n", __FUNCTION__, pRtspSess->cur_state, method);
            }
            break;
    }/* end of current state switch */

}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void RTSP_remove_msg(int len, RTSP_buffer * rtsp)
{
	rtsp->in_size -= len;
	if (rtsp->in_size && len)
	{
		memmove(rtsp->in_buffer, &(rtsp->in_buffer[len]), RTSP_BUFFERSIZE - len);
		memset(&(rtsp->in_buffer[RTSP_BUFFERSIZE - len]), 0, len);
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void RTSP_discard_msg(RTSP_buffer * rtsp)
{
	int hlen, blen;
	int ret_RTSP_full_msg_rcvd=0;
	ret_RTSP_full_msg_rcvd=RTSP_full_msg_rcvd(rtsp, &hlen, &blen);

	if(play_flag==1)
	{
		if (ret_RTSP_full_msg_rcvd> 0)
		{
			RTSP_remove_msg(hlen + blen, rtsp);
		}
		play_flag=0;
	}
	else
	{
		if(ret_RTSP_full_msg_rcvd==2 ||ret_RTSP_full_msg_rcvd==0 ||ret_RTSP_full_msg_rcvd==-1)
		{
			rtsp->out_size=0;
			memset(rtsp->out_buffer, 0, rtsp->out_size);	
			memset(rtsp->in_buffer, 0, rtsp->in_size);	
			rtsp->in_size=0;
		}
		else if (ret_RTSP_full_msg_rcvd> 0)
		{
			RTSP_remove_msg(hlen + blen, rtsp);
			memset(rtsp->in_buffer, 0, rtsp->in_size);
			rtsp->in_size=0;
		}
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int RTSP_handler(RTSP_buffer *pRtspBuf)
{
	int s32Meth;

	while(pRtspBuf->in_size)
	{
		s32Meth = RTSP_validate_method(pRtspBuf);
		if(s32Meth==RTSP_ID_TEARDOWN)
		{
			return RTSP_ID_TEARDOWN;
		}
		if (s32Meth < 0)
		{
			send_reply(400, NULL, pRtspBuf);
		}
		else
		{
			RTSP_state_machine(pRtspBuf, s32Meth);
		}
		RTSP_discard_msg(pRtspBuf);
	}
	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
 

int RtspServer(RTSP_buffer *rtsp)
{
	/*读写I/O描述集*/
	struct timeval t;
	fd_set rset,wset;   
	int size;
	static char buffer[RTSP_BUFFERSIZE+1]; /* +1 to control the final '\0'*/
	int n=0;
	int res;
	struct sockaddr ClientAddr;
	if (rtsp == NULL)
	{
		return ERR_NOERROR;
	}
	/*变量初始化*/
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	t.tv_sec=0;				/*select 时间间隔*/
	t.tv_usec=1000;
	FD_SET(rtsp->fd,&rset);
	if (select(g_s32Maxfd+1,&rset,0,0,&t)<0)
	{
		 printf("RTSP Debug : select error %s %d\n", __FILE__, __LINE__);
		return ERR_NOERROR; //errore interno al server
	}
	/*有可供读进的rtsp包*/
	if (FD_ISSET(rtsp->fd,&rset))
	{
		memset(buffer,0,sizeof(buffer));
		size=sizeof(buffer)-1;  /*最后一位用于填充字符串结束标识*/

		/*读入数据到缓冲区中*/
		n= tcp_read(rtsp->fd, buffer, size, &ClientAddr);
		if (n==0)
		{
			return ERR_CONNECTION_CLOSE;
		}

		if (n<0)
		{
			 printf("RTSP Debug : read() error %s %d\n", __FILE__, __LINE__);
			return ERR_GENERIC;
		}

		//检查读入的数据是否产生溢出
		if (rtsp->in_size+n>RTSP_BUFFERSIZE)
		{
			 printf("RTSP Debug : RTSP buffer overflow (input RTSP message is most likely invalid).\n");
			send_reply(500, NULL, rtsp);
			return ERR_GENERIC;//数据溢出错误
		}

		if(n>0  )
		{
			/*填充数据*/
			memcpy(&(rtsp->in_buffer[rtsp->in_size]),buffer,n);
			rtsp->in_size+=n;
			//清空buffer
			memset(buffer, 0, n);
			n=0;
			//添加客户端地址信息
			memcpy(	&rtsp->stClientAddr, &ClientAddr, sizeof(ClientAddr));

			/*处理缓冲区的数据，进行rtsp处理*/
			if ((res=RTSP_handler(rtsp))==ERR_GENERIC)
			{
				printf("RTSP Debug : Invalid input message.\n");
				return ERR_NOERROR;
			}
			if (res==RTSP_ID_TEARDOWN)
			{
				rtsp->out_size = 0;
				memset(rtsp->out_buffer, 0,sizeof(rtsp->out_buffer));
				return  ERR_CONNECTION_CLOSE;
			}
		}
	}

	/*有发送数据*/
	if (rtsp->out_size>0)
	{
		n= tcp_write(rtsp->fd,rtsp->out_buffer,rtsp->out_size);
		if (n<0)
		{
			 printf("RTSP Debug : tcp_write error %s %i\n", __FILE__, __LINE__);
			return ERR_GENERIC; //errore interno al server
		}
		//清空发送缓冲区
		memset(rtsp->out_buffer, 0, rtsp->out_size);
		rtsp->out_size = 0;
	}




	return ERR_NOERROR;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void ScheduleConnections(RTSP_buffer **rtsp_list, int *conn_count)
{
	int res;
	RTSP_buffer *pRtsp=*rtsp_list,*pRtspN=NULL;
	RTP_session *r=NULL;

	while (pRtsp!=NULL)
	{
		if ((res = RtspServer(pRtsp))!=ERR_NOERROR)
		{
			if (res==ERR_CONNECTION_CLOSE || res==ERR_GENERIC)
			{
				/*连接已经关闭*/
				if (res==ERR_CONNECTION_CLOSE)
				{
					 printf("RTSP Debug : fd:%d,RTSP connection closed by client.\n",pRtsp->fd);
				}
				else
				{
					 printf("RTSP Debug : fd:%d,RTSP connection closed by server.\n",pRtsp->fd);
				}

				/*客户端在发送TEARDOWN 之前就截断了连接，但是会话却没有被释放*/

				if (pRtsp->session_list!=NULL)
				{
					if(pRtsp->session_list->rtp_session!=NULL)	
					{
						r=pRtsp->session_list->rtp_session;
						/*释放所有会话*/
						schedule_remove(r->sched_id);
						usleep(1000);
						RtpDelete((r));
						free(pRtsp->session_list->rtp_session);
						if(audio_flag==1)
						{
							if(pRtsp->session_list->rtp_session_audio!=NULL)
							{
								r=pRtsp->session_list->rtp_session_audio;
								RtpDelete((r));
								free(pRtsp->session_list->rtp_session_audio);
							}
						}	
						g_s32DoPlay--;
					}
					/*释放链表头指针*/
					free(pRtsp->session_list);
					pRtsp->session_list=NULL;

					

					printf("RTSP Debug : [%s : %d] g_s32DoPlay : %i\n\n",__func__,__LINE__,g_s32DoPlay);
					if (g_s32DoPlay == 0) 
					{
						printf("RTSP Debug : user abort! no user online now resetfifo\n");
						ringreset;
						rtsp_on=0;
						usleep(400);
						ringfree();
						/* 重新将所有可用的RTP端口号放入到port_pool[MAX_SESSION] 中 */
						RTP_port_pool_init(RTP_DEFAULT_PORT);
					}
				}

				close(pRtsp->fd);
				--*conn_count;
				num_conn--;

				/*Release rtsp buffer*/
				if (pRtsp==*rtsp_list)
				{
					//The first element of the linked list is wrong, then pRtspN is empty.
					if(pRtsp->next==NULL)
					{
						printf("RTSP Debug : last and first\n");	
						free(pRtsp);
						pRtsp=NULL;	
						*rtsp_list=NULL;
					}
					else
					{
						printf("RTSP Debug : first \n");
						*rtsp_list=pRtsp->next;
						free(pRtsp);
						printf("RTSP Debug : dell current fd:%d\n",pRtsp->fd);
						pRtsp=*rtsp_list;
					}
				}
				else if(pRtsp->next==NULL)
				{
					pRtspN=(*rtsp_list);
					printf("RTSP Debug : else if(pRtsp->next==NULL)	dell current fd:%d\n",pRtsp->fd);
					while(pRtspN->next!=pRtsp)
					{
						pRtspN=pRtspN->next;
					}
					pRtspN->next=NULL;
					free(pRtsp);
					pRtsp=NULL;	
				}
				else			
				{

					pRtspN=(*rtsp_list);
					printf("RTSP Debug : else	dell current fd:%d\n",pRtsp->fd);
					while(pRtspN->next!=pRtsp)
					{
						pRtspN=pRtspN->next;
					}
					pRtspN->next=pRtsp->next;
					free(pRtsp);
					pRtsp=pRtspN->next;
				}

			}
			else
			{	
				printf("RTSP Debug : current fd:%d\n",pRtsp->fd);
				pRtsp = pRtsp->next;
			}
		}
		else
		{
			pRtspN = pRtsp;
			pRtsp = pRtsp->next;
		}
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void RTP_port_pool_init(int port)
{
	int i;
	s_u32StartPort = port;
	for (i=0; i<MAX_CONNECTION; ++i)
	{
		s_uPortPool[i] = i+s_u32StartPort;
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void delete_last_clients(RTSP_buffer **ppRtspList, int *conn_count)
{
	RTSP_buffer *pRtsp=NULL;
	RTP_session *r=NULL;
	if (*ppRtspList!=NULL)
	{
		pRtsp=*ppRtspList;
		while (pRtsp!=NULL )
		{
			if (pRtsp->session_list!=NULL)
				{
					if(pRtsp->session_list->rtp_session!=NULL)	
					{
						r=pRtsp->session_list->rtp_session;
						/*释放所有会话*/
						schedule_remove(r->sched_id);
						usleep(500*1000);
						RtpDelete((r));
						
						if(audio_flag==1)
						{
							if(pRtsp->session_list->rtp_session_audio!=NULL)
							{
								r=pRtsp->session_list->rtp_session_audio;
								RtpDelete((r));
							}
						}			
					}
					/*释放链表头指针*/
					free(pRtsp->session_list);
					pRtsp->session_list=NULL;

					g_s32DoPlay--;

					if (g_s32DoPlay == 0) 
					{
						printf("RTSP Debug : user abort! no user online now resetfifo\n");
						ringreset();
						rtsp_on=0;
						usleep(400);
						ringfree();
						/* 重新将所有可用的RTP端口号放入到port_pool[MAX_SESSION] 中 */
						RTP_port_pool_init(RTP_DEFAULT_PORT);
					}
				}
				close(pRtsp->fd);
				--*conn_count;
				num_conn--;
				printf("RTSP Debug : [%s : %d] pRtsp->next : %p , pRtsp : %p num_conn %i\n",__func__,__LINE__,pRtsp->next,pRtsp,num_conn);
				if(pRtsp->next==NULL)
				{
					free(pRtsp);	
					pRtsp=NULL;
					*ppRtspList=NULL;
					break;
				}
				else
				{
					*ppRtspList=pRtsp->next;
					free(pRtsp);
					pRtsp=NULL;
					pRtsp=*ppRtspList;
					
				}
		}
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
char last_ip[100];
int checkipstatus()
{
	
	struct ifreq ifr;
	char *IPbuffer;
	int test_ip=0;
	char IP[100]={0};
	/*TO GET ITS OWN IP ADDRESS*/
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;
	/* I want IP address attached to "eth0" */
	strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1);
	if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
	{
		strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
		if(ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
		{
			printf("RTSP Debug : Failed to get host eth0 or wlan0 ip\n");
		}
	}
	close(sockfd);
	IPbuffer = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	strcpy(IP,IPbuffer);
	if(strcmp(last_ip,IP)!=0)
	{
		printf("RTSP Debug : last_ip:%s 	Current IP:%s\n",last_ip,IP);
		memset(last_ip,0,sizeof(last_ip));
		strcpy(last_ip,IP);
		return 1;
	}
	return 0;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/

int last_connection_interface=0;
void EventLoop(int s32MainFd)
{
	static int s32ConCnt = 0;//已经连接的客户端数
	int s32Fd = -1;
	static RTSP_buffer *pRtspList=NULL;
	RTSP_buffer *p=NULL;
	unsigned int u32FdFound;
	if (s32ConCnt!=-1)
	{
		s32Fd= tcp_accept(s32MainFd);
	}
	
	/*处理新创建的连接*/
	
	if (s32Fd >= 0)
	{
		/*查找列表中是否存在此连接的socket*/
		for (u32FdFound=0,p=pRtspList; p!=NULL; p=p->next)
		{
			if (p->fd == s32Fd)
			{
				u32FdFound=1;
				break;
			}
		}
		if (!u32FdFound)
		{
			/*创建一个连接，增加一个客户端*/
			if (s32ConCnt<MAX_CONNECTION)
			{
				++s32ConCnt;
				AddClient(&pRtspList,s32Fd);
			}
			else
			{
				 printf( "RTSP Debug : exceed the MAX client, ignore this connecting\n");
				return;
			}
			num_conn++;
			printf("RTSP Debug : [%s:%d] num_conn : %i\n",__func__,__LINE__,num_conn);
		}
	}
	/*If IP has changed*/
	if(checkipstatus()==1 || network_issue_flag==1)
	{
		delete_last_clients(&pRtspList,&s32ConCnt);
		network_issue_flag=0;
	}
	/*If RTSP_Server_Deinit has been called by Server_Deinit*/
	if(rtsp_quit_flag==1)
	{
		delete_last_clients(&pRtspList,&s32ConCnt);
		g_s32Quit=1;
	}
	if(pRtspList!=NULL)
	{
		ScheduleConnections(&pRtspList,&s32ConCnt);
	}
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
char * base64_encode(const unsigned char * bindata, char * base64, int binlength)
{
	int i, j;
	unsigned char current;
	char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for(i = 0, j = 0 ; i < binlength ; i += 3)
	{
		current = (bindata[i] >> 2) ;
		current &= (unsigned char)0x3F;

		base64[j++] = base64char[(int)current];

		current = ((unsigned char)(bindata[i] << 4)) & ((unsigned char)0x30) ;
		if(i + 1 >= binlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';
			base64[j++] = '=';
			break;
		}
		current |= ((unsigned char)(bindata[i+1] >> 4)) & ((unsigned char) 0x0F);
		base64[j++] = base64char[(int)current];


		current = ((unsigned char)(bindata[i+1] << 2)) & ((unsigned char)0x3C) ;
		if(i + 2 >= binlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';
			break;
		}
		current |= ((unsigned char)(bindata[i+2] >> 6)) & ((unsigned char) 0x03);
		base64[j++] = base64char[(int)current];

		current = ((unsigned char)bindata[i+2]) & ((unsigned char)0x3F) ;
		base64[j++] = base64char[(int)current];
	}
	base64[j] = '\0';
	return base64;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void base64_encode2(char *in, const int in_len, char *out, int out_len)
{
	static const char *codes ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	char *p = out;
	int times = in_len / 3;
	int i;

	for(i=0; i<times; ++i)
	{
		*p++ = codes[(in[0] >> 2) & 0x3f];
		*p++ = codes[((in[0] << 4) & 0x30) + ((in[1] >> 4) & 0xf)];
		*p++ = codes[((in[1] << 2) & 0x3c) + ((in[2] >> 6) & 0x3)];
		*p++ = codes[in[2] & 0x3f];
		in += 3;
	}
	if(times * 3 + 1 == in_len) 
	{
		*p++ = codes[(in[0] >> 2) & 0x3f];
		*p++ = codes[((in[0] << 4) & 0x30) + ((in[1] >> 4) & 0xf)];
		*p++ = '=';
		*p++ = '=';
	}
	if(times * 3 + 2 == in_len) 
	{
		*p++ = codes[(in[0] >> 2) & 0x3f];
		*p++ = codes[((in[0] << 4) & 0x30) + ((in[1] >> 4) & 0xf)];
		*p++ = codes[((in[1] << 2) & 0x3c)];
		*p++ = '=';
	}
	*p = 0;
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void UpdateSps(unsigned char *data,int len)
{
	if(len>21)
		return ;

	sprintf(psp.base64profileid,"%x%x%x",data[1],data[2],data[3]);//sps[0] 0x67
	base64_encode2(data, len, psp.base64sps, 512);
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void UpdatePps(unsigned char *data,int len)
{
	if(len>21)
		return ;
	base64_encode2(data, len, psp.base64pps, 512);

}


