#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "spindump_util.h"
#include "spindump_analyze.h"
#include "spindump_analyze_tcp.h"
#include "spindump_analyze_tcp_parser.h"


void print_binary(uint8_t val);
void print_header(const unsigned char* header);

//ADDED TO ENABLE EFM SUPPORT FOR TCP
enum spindump_tcp_EFM_technique
spindump_analyze_tcp_parser_check_EFM(const unsigned char* header) {

  //
  // Sanity checks
  //

  spindump_assert(header != 0);

  // 
  // Parse the TCP header. The structure is from RFC 793:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |          Source Port          |       Destination Port        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                        Sequence Number                        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Acknowledgment Number                      |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |  Data | |*|*|A|C|E|U|A|P|R|S|F|                               |
  //  | Offset| |*| |E|W|C|R|C|S|S|Y|I|            Window             |
  //  |       | | | | |R|E|G|K|H|T|N|N|                               |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |           Checksum            |         Urgent Pointer        |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                    Options                    |    Padding    |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //  |                             data                              |
  //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //

  // * this field is used to carry a time EFM marking, through either the SPIN BIT or the DELAY BIT technique
  // ** this field is used to carry a loss EFM marking, through the Q bit technique 
  
  uint8_t off_rsvd;
  
  //spindump_decodebyte(off_rsvd,header,pos);           // ff_rsvd gets its memory allocated
  off_rsvd = header[12];

/*
  if ((*off_rsvd && 0b00000110) == 0b00000100){  //SPIN BIT
    return spindump_tcp_EFM_spin;
  }
  else if ((*off_rsvd && 0b00000110) == 0b00000010){  //DELAY BIT
    return spindump_tcp_EFM_delay;
  }
  else if ((*off_rsvd && 0b00000110) == 0b00000110){  //DELAY BIT + Q BIT
    return spindump_tcp_EFM_delay_plus_q;
  }
  return spindump_tcp_no_EFM;
  */

//fprintf(stderr,"header = ");
//print_header(header);

//fprintf(stderr,"offset = ");
print_binary(off_rsvd);

if ((off_rsvd & 0x06) == 0x04){  //SPIN BIT
    fprintf(stderr, "SPIN IS ACTIVE\n");
    return spindump_tcp_EFM_spin;
  }
  else if ((off_rsvd & 0x06) == 0x02){  //DELAY BIT
    fprintf(stderr, "DELAY IS ACTIVE\n");
    return spindump_tcp_EFM_delay;
  }
  else if ((off_rsvd & 0x06) == 0x06){  //DELAY BIT + Q BIT
    fprintf(stderr, "DELAY*Q ARE ACTIVE\n");
    return spindump_tcp_EFM_delay_plus_q;
  }
  fprintf(stderr, "NO MARKING IS ACTIVE\n");
  return spindump_tcp_no_EFM;
}

int
spindump_analyze_tcp_parser_gettimebit(const unsigned char* header) {
  uint8_t off_rsvd;

  //
  // Sanity check
  //
  spindump_assert(header != 0);
  
  off_rsvd = header[12];

  //if ((*off_rsvd && 0b00000010) == 0b00000010){  //SPIN OR DELAY BIT
  if ((off_rsvd & 0x02) == 0x02){  //SPIN OR DELAY BIT
    return 1;
  }
  else return 0;
}

void
print_binary(uint8_t 
val) {
  char a = val;
  int i;
  for (i = 0; i < 8; i++) {
      fprintf(stderr, "%d", !!((a << i) & 0x80));
  }
  fprintf(stderr, "\n");
}

void
print_header(const unsigned char* header) {
  char a;
  int i, j;
  for(j=0;j<20;j++){
    a=header[j];
    for (i = 0; i < 8; i++) {
        fprintf(stderr, "%d", !!((a << i) & 0x80));
    }
    fprintf(stderr, " ");
  }
  fprintf(stderr, "\n");
}