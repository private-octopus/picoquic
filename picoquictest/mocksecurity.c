/*
 * Pseudo security handshake. The requirements are to simulate a 
 * TLS 1.3 exchange, so it can be carried with QUIC.
 *
 * The requirements are:
 * - Manage a context,
 * - Set up a connection:
 *   -- initial packet from client, carrying client's transport parameters
 *      in a quic extension.
 *   -- accept from server, including server's transport parameters in
 *      quic extension
 *   -- finished by client.
 * - Create a key per connection. 
 * - Create a resume token.
 * - Signal 0-RTT key available if appropriate
 * - Signal 1-RTT key available if appropriate
 */