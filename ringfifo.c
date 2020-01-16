#include<stdio.h>
#include<ctype.h>
#include <stdlib.h>
#include <string.h>
#include "ringfifo.h"
#include "rtputils.h"



int iput = 0; /* 环形缓冲区的当前放入位置 */
int iget = 0; /* 缓冲区的当前取出位置 */
int n = 0; /* 环形缓冲区中的元素总数量 */

struct ringbuf ringfifo[NMAX];
extern int UpdateSpsOrPps(unsigned char *data,int frame_type,int len);
/* 环形缓冲区的地址编号计算函数，如果到达唤醒缓冲区的尾部，将绕回到头部。
环形缓冲区的有效地址编号为：0到(NMAX-1)
*/
void ringmalloc(int size)
{
	int i;
	for(i =0; i<NMAX; i++)
	{
		ringfifo[i].buffer = calloc(1,size);
		if(ringfifo[i].buffer!=NULL)
		{
			memset(ringfifo[i].buffer,0,size);
		}
		ringfifo[i].size = 0;
		ringfifo[i].frame_type = 0;
		ringfifo[i].data_type = 0;	
	}
	iput = 0; /* 环形缓冲区的当前放入位置 */
	iget = 0; /* 缓冲区的当前取出位置 */
	n = 0; /* 环形缓冲区中的元素总数量 */
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void ringreset()
{
	iput = 0; /* 环形缓冲区的当前放入位置 */
	iget = 0; /* 缓冲区的当前取出位置 */
	n = 0; /* 环形缓冲区中的元素总数量 */
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void ringfree(void)
{
	int i;
	 printf("RTSP Debug : begin free mem\n");
	for(i =0; i<NMAX; i++)
	{
		free(ringfifo[i].buffer);
		ringfifo[i].buffer = NULL;
		ringfifo[i].size = 0;
	}
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
int addring(int i)
{
	return (i+1) == NMAX ? 0 : i+1;
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
/* 从环形缓冲区中取一个元素 */

int ringget(struct ringbuf *getinfo)
{
	int Pos;
	if(n>0)
	{
		Pos = iget;
		iget = addring(iget);
		n--;
		getinfo->buffer = (ringfifo[Pos].buffer);
		getinfo->frame_type = ringfifo[Pos].frame_type;
		getinfo->data_type = ringfifo[Pos].data_type;	
		getinfo->size = ringfifo[Pos].size;
		return ringfifo[Pos].size;
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
/* 向环形缓冲区中放入一个元素*/
void ringput(unsigned char *buffer,int size,int encode_type)
{

	if(n<NMAX)
	{
		memcpy(ringfifo[iput].buffer,buffer,size);
		ringfifo[iput].size= size;
		ringfifo[iput].frame_type = encode_type;
		iput = addring(iput);
		n++;
	}
	else
	{
		  printf("RTSP Debug : Buffer is full\n");
	}
}

/**************************************************************************************************
**
**
**
**************************************************************************************************/
