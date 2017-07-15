#include <mongoose.h>
#include <syslog.h>
#include <pty.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

const char *http_auth[5];
static struct mg_serve_http_opts http_server_opts;

static void http_ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	switch (ev) {
	case MG_EV_HTTP_REQUEST: {
			struct http_message *hm = (struct http_message *)ev_data;
			mg_serve_http(nc, hm, http_server_opts); /* Serve static content */
			break;
		}
	}
}

static void mqtt_ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	switch (ev) {
	case MG_EV_CONNECT: {
			struct mg_send_mqtt_handshake_opts opts;
			int err = *(int *)ev_data;
			char client_id[32] = "";
			if (err) {
				syslog(LOG_ERR, "connect() failed: %s", strerror(err));
				return;
			}
			
			memset(&opts, 0, sizeof(opts));
			opts.flags |= MG_MQTT_CLEAN_SESSION;

			snprintf(client_id, sizeof(client_id), "xterminal:%f", mg_time());
			
			mg_set_protocol_mqtt(nc);
			mg_send_mqtt_handshake_opt(nc, client_id, opts);
			break;
		}

	case MG_EV_MQTT_CONNACK: {

			break;
		}

	case MG_EV_MQTT_PUBLISH: {

			
			break;
		}
	}
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

static  void usage(const char *program)
{
	printf("Usage:%s [options]\n", program);
	printf("     -d              Log to stderr\n"
        "     --mqtt-port     default is 1883\n"
        "     --http-port     default is 8443\n"
        "     --document      default is ./www\n"
        "     --http-auth     set http auth(username:password), default is xterminal:xterminal\n"
        "     --ssl-cert      default is ./server.pem\n"
        "     --ssl-key       default is ./server.key\n");
	
	exit(0);
}

int main(int argc, char *argv[])
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal sig_watcher;
	int log_to_stderr = 0;
	const char *mqtt_port = "1883", *http_port = "8443";
	const char *ssl_cert = "server.pem", *ssl_key = "server.key";
	int http_auth_cnt = 0;
	struct mg_bind_opts bind_opts;
	
	struct mg_mgr mgr;
	struct mg_connection *nc;
	struct option longopts[] = {
		{"help",  no_argument, NULL, 'h'},
		{"mqtt-port", required_argument, NULL, 0},
		{"http-port", required_argument, NULL, 0},
		{"document", required_argument, NULL, 0},
		{"http-auth", required_argument, NULL, 0},
		{"ssl-cert", required_argument, NULL, 0},
		{"ssl-key", required_argument, NULL, 0},
		{0, 0, 0, 0}
	};
	
	while (1) {
		int c, option_index;
		c = getopt_long(argc, argv, "hd", longopts, &option_index);
		if (c == -1)
			break;
		
		switch (c) {
		case 'd':
			log_to_stderr = 1;
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "mqtt-port"))
				mqtt_port = optarg;
			else if (!strcmp(longopts[option_index].name, "http-port"))
				http_port = optarg;
			else if (!strcmp(longopts[option_index].name, "document"))
				http_server_opts.document_root = optarg;
			else if (!strcmp(longopts[option_index].name, "http-auth"))
				http_auth[http_auth_cnt++] = optarg;
			else if (!strcmp(longopts[option_index].name, "ssl-cert"))
				ssl_cert = optarg;
			else if (!strcmp(longopts[option_index].name, "ssl-key"))
				ssl_key = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	
	if (log_to_stderr)
		openlog("xterminal broker", LOG_ODELAY | LOG_PERROR, LOG_USER);
	else
		openlog("xterminal broker", LOG_ODELAY, LOG_USER);
	
	mg_mgr_init(&mgr, NULL, loop);
	
	ev_signal_init(&sig_watcher, signal_cb, SIGINT);
	ev_signal_start(loop, &sig_watcher);

	nc = mg_connect(&mgr, mqtt_port, mqtt_ev_handler);
	if (!nc) {
		syslog(LOG_ERR, "mg_connect(%s) failed", mqtt_port);
		goto err;
	}
	
	memset(&bind_opts, 0, sizeof(bind_opts));
	bind_opts.ssl_cert = ssl_cert;
	bind_opts.ssl_key = ssl_key;
	
	nc = mg_bind_opt(&mgr, http_port, http_ev_handler, bind_opts);
	if (nc == NULL) {
		syslog(LOG_ERR, "Failed to create listener on %s", http_port);
		goto err;
	}
	
	/* Set up HTTP server parameters */
	mg_set_protocol_http_websocket(nc);
	
	ev_run(loop, 0);

err:
	mg_mgr_free(&mgr);

	return 0;
}