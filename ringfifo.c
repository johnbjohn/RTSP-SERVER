#include<stdio.h>
#include<ctype.h>
#include <stdlib.h>
#include <string.h>
#include "ringfifo.h"
#include "rtputils.h"



int iput = 0; /* ���λ������ĵ�ǰ����λ�� */
int iget = 0; /* �������ĵ�ǰȡ��λ�� */
int n = 0; /* ���λ������е�Ԫ�������� */

struct ringbuf ringfifo[NMAX];
extern int UpdateSpsOrPps(unsigned char *data,int frame_type,int len);
/* ���λ������ĵ�ַ��ż��㺯����������﻽�ѻ�������β�������ƻص�ͷ����
���λ���������Ч��ַ���Ϊ��0��(NMAX-1)
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
	iput = 0; /* ���λ������ĵ�ǰ����λ�� */
	iget = 0; /* �������ĵ�ǰȡ��λ�� */
	n = 0; /* ���λ������е�Ԫ�������� */
}
/**************************************************************************************************
**
**
**
**************************************************************************************************/
void ringreset()
{
	iput = 0; /* ���λ������ĵ�ǰ����λ�� */
	iget = 0; /* �������ĵ�ǰȡ��λ�� */
	n = 0; /* ���λ������е�Ԫ�������� */
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
/* �ӻ��λ�������ȡһ��Ԫ�� */

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
/* ���λ������з���һ��Ԫ��*/
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
