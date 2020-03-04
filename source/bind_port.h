/*
 * NAME: bind_port
 * Synopsis: Bind UDP port for client (port is higher that start_port + 5 till start_port + 50
 * if not find free port exist from program (should be correct to handle this by laucher)
 * args:
 * IN:
 * None
 * OUT:
 * id from bind port
 *
 */
#ifndef BIND_PORT_H

int bind_port();

#define BIND_PORT_H
#endif

