#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#define MAX_LENGTH 256
#define SLEEP_TIME 4

struct TxRx_Pair {
	unsigned int txCount;
	unsigned int rxCount;
};
char temp_buff[20],buff[MAX_LENGTH];

void update_stat_buffer(long key, long txC, long rxC)
{
	sprintf(temp_buff, "CAN%ld = %ld / %ld  ",key, txC,rxC);
	if(strlen(buff) == 0)
	{
		strcpy(buff,temp_buff);
	}
	else
	{
		strcpy(buff+strlen(buff),temp_buff);
	}
}
int main(int argc, char **argv)
{
	char filename[MAX_LENGTH];
	long key,next_key, value,size;	
	struct TxRx_Pair pair;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	printf("***eBPF based Can Bus Trace - Statistics***\nControllerName: Tx/Rx count\n");
	while (1) 
	{
		sleep(SLEEP_TIME);
		key = next_key = -1; //reset
		buff[0]='\0';
		//iterate over the map_fd[0], the first ebpf map reference in .ko file
		while(bpf_map_get_next_key( map_fd[0], &key,&next_key) == 0 )
		{ 	
			bpf_map_lookup_elem(map_fd[0], &next_key, &pair); 
			key=next_key;
			update_stat_buffer(next_key,pair.txCount,pair.rxCount);
		}
		printf("%s\r", buff);// display to terminal
		fflush(stdout);
	}
	print('\n');

	return 0;
}
