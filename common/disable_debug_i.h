/* disable_debug_i.h
 *
 * This file should be included in any C file that wishes to disable
 * the debug functions.
 */

#ifndef DISABLE_DEBUG_I_H_FILE
#define DISABLE_DEBUG_I_H_FILE

#define ssh_log(...)
#define dump_mem(...)
#define dump_str(...)
#define dump_packet(...)
#define dump_packet_reader(...)
#define dump_packet(...)
#define dump_kexinit_packet(...)
#define dump_kexinit_packet_reader(...)
#define debug_gen_packet(...)
#define debug_gen_string_packet(...)

#endif /* DISABLE_DEBUG_I_H_FILE */
