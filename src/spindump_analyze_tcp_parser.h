//ADDED TO ENABLE EFM SUPPORT FOR TCP
#include "spindump_connections.h"

enum spindump_tcp_EFM_technique spindump_analyze_tcp_parser_check_EFM(const unsigned char* header);
int spindump_analyze_tcp_parser_gettimebit(const unsigned char* header);
