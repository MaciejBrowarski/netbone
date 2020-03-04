#include <stdint.h>
/*
 * 0.1 - created
 * 0.2 2016 June - add debug_xml_parse
 */


extern char log_dir[PATH_MAX];

/*
 * debug variables
 */
extern uint8_t debug;
extern uint8_t debug_calc_crc;
extern uint8_t debug_client_request_get;
extern uint8_t debug_client_request;
extern uint8_t debug_code_encode;
extern uint8_t debug_get_list_meta_data;
extern uint8_t debug_main_loop;
extern uint8_t debug_request_get;
extern uint8_t debug_request_list;
extern uint8_t debug_get_list_meta_data;
extern uint8_t debug_checker;
extern uint8_t debug_get_object;
extern uint8_t debug_checker_buffer;
extern uint8_t debug_request_put;
extern uint8_t debug_sendd_name_version;
extern uint8_t debug_send_packet;
extern uint8_t debug_send_request;
extern uint8_t debug_tcp_server;
extern uint8_t debug_xml_parse;
extern uint8_t debug_memory;

#if defined SMS
extern char *hostname_gw;
extern int32_t port_gw;
extern int ssl_req;
extern char *pem_key;
extern char *url;
extern char *confirm;
#endif

/*
 * function name: read_file
 * synopisis: read parameters from configuration file
 * paramters are written to global variables
 *
 * agruments:
 *  in:
 *      str - name of configuration file
 *      buf - array where IP should be written
 *  dynamic - 0 - first read of cfg, 1 - reload - only dynamic parameters changes
 *  out:
 * 0 - problem with cfg read
 * 1 - data read properly
 *
*/
int read_file(char *, char **, uint16_t);

