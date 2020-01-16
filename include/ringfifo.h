#ifndef RINGFIFO_H_
#define RINGFIFO_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define NMAX 30


struct ringbuf {
    	unsigned char *buffer;
	int frame_type;
	int data_type;
    	int size;
};

int addring (int i);
int ringget(struct ringbuf *getinfo);
void ringput(unsigned char *buffer,int size,int encode_type);
void ringfree();
void ringmalloc(int size);
void ringreset();


#ifdef __cplusplus
}
#endif

#endif


