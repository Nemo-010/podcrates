/*
 * The TURN server of libjuice on 127.0.0.1 for scripts/ci/turn-tests.sh
 * (T-403, call C576): one made-up user, its realm and a port. libjuice's
 * 401 offers SHA-256 and announces USERHASH, which coturn does not.
 *
 *   juice-turn PORT USER PASSWORD REALM
 *
 * It runs until SIGTERM or SIGINT.
 */
#include <juice/juice.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	if (argc != 5) {
		fprintf(stderr, "usage: juice-turn PORT USER PASSWORD REALM\n");
		return 64;
	}
	/* Blocked before the server starts its thread, so that the thread
	 * inherits the mask and sigwait below takes the signal. */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	juice_set_log_level(JUICE_LOG_LEVEL_INFO);
	juice_server_credentials_t user = {argv[2], argv[3], 8};
	juice_server_config_t config = {0};
	config.credentials = &user;
	config.credentials_count = 1;
	config.max_allocations = 16;
	config.max_peers = 16;
	config.bind_address = "127.0.0.1";
	config.port = (uint16_t)atoi(argv[1]);
	config.realm = argv[4];
	juice_server_t *server = juice_server_create(&config);
	if (!server) {
		fprintf(stderr, "juice-turn: libjuice made no server on port %s\n", argv[1]);
		return 1;
	}
	printf("juice-turn: 127.0.0.1:%u\n", (unsigned)juice_server_get_port(server));
	fflush(stdout);
	int sig;
	sigwait(&set, &sig);
	juice_server_destroy(server);
	return 0;
}
