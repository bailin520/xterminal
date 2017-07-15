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
#include "list.h"

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

#define MAX_HTTP_AUTH	5
const char *http_auth[MAX_HTTP_AUTH] = {"xterminal:xterminal"};

static struct mg_serve_http_opts http_server_opts = {
	.index_files = "xterminal.html",
	.document_root = "www"
};

#define HTTP_SESSION_COOKIE_NAME "mgs"
/* In our example sessions are destroyed after 30 seconds of inactivity. */
#define HTTP_SESSION_TTL 30.0

/* HTTP Session information structure. */
struct http_session {
	uint64_t id;
	double last_used;
	char *username;
	struct list_head node;
};

#define DEVICE_TTL	30.0

struct device {
	char mac[13];
	int last_active;
	struct mg_connection *nc;
	struct list_head node;
};

struct tty_session {
	char mac[13];
	uint64_t id;
	char topic_data[128];
	char topic_disconnect[128];
	struct mg_connection *nc;
	struct list_head node;
};

LIST_HEAD(http_sessions); /* HTTP Session list */
LIST_HEAD(devices_list); /* devices list */
LIST_HEAD(tty_sessions); /* tty_session list */

static int check_pass(const char *username, const char *password)
{
	int i = 0;
	char buf[128];
	
	snprintf(buf, sizeof(buf), "%s:%s", username, password);
	for (i = 0; i < MAX_HTTP_AUTH; i++) {
		if (http_auth[i] && !strcmp(http_auth[i], buf))
			return 1;
	}
	
	return 0;
}


/*
 * Parses the session cookie and returns a pointer to the session struct
 * or NULL if not found.
 */
static struct http_session *get_http_session(struct http_message *hm)
{
	char ssid[21];
	uint64_t sid;
	struct http_session *s;
	struct mg_str *cookie_header = mg_get_http_header(hm, "cookie");
	
	if (cookie_header == NULL)
		return NULL;
	
	if (!mg_http_parse_header(cookie_header, HTTP_SESSION_COOKIE_NAME, ssid, sizeof(ssid)))
		return NULL;
	
	sid = strtoull(ssid, NULL, 16);
	
	list_for_each_entry(s, &http_sessions, node) {
		if (s->id == sid) {
			s->last_used = mg_time();
			return s;
		}
	}
	
	return NULL;
}

/* Destroys the session state. */
static void destroy_http_session(struct http_session *s)
{
	list_del(&s->node);
	free(s->username);
	free(s);
}

/* Creates a new http session for the user. */
static struct http_session *create_http_session(const char *username, const struct http_message *hm)
{
	unsigned char digest[20];
	/* Find first available slot or use the oldest one. */
	struct http_session *s = calloc(1, sizeof(struct http_session));
	if (!s)
		return NULL;
	
	/* Initialize new session. */
	s->last_used = mg_time();
	s->username = strdup(username);
	
	/* Create an ID by putting various volatiles into a pot and stirring. */
	cs_sha1_ctx ctx;
	cs_sha1_init(&ctx);
	cs_sha1_update(&ctx, (const unsigned char *)hm->message.p, hm->message.len);
	cs_sha1_update(&ctx, (const unsigned char *)s, sizeof(*s));
	
	cs_sha1_final(digest, &ctx);
	s->id = *((uint64_t *)digest);

	list_add(&s->node, &http_sessions);
	
	return s;
}

static int http_login(struct mg_connection *nc, struct http_message *hm)
{
	struct http_session *s;
	struct mg_str *uri = &hm->uri;
	
	if (memmem(uri->p, uri->len, ".js", 3) || memmem(uri->p, uri->len, ".css", 3))
		return 1;
	
	if (!mg_vcmp(uri, "/login.html")) {
		int ul, pl;
		char username[50], password[50];
		
		if (mg_vcmp(&hm->method, "POST"))
			return 1;
		
		ul = mg_get_http_var(&hm->body, "username", username, sizeof(username));
		pl = mg_get_http_var(&hm->body, "password", password, sizeof(password));
		
		if (ul > 0 && pl > 0) {
			if (check_pass(username, password)) {
				struct http_session *s = create_http_session(username, hm);
				char shead[100];

				if (!s) {
					mg_http_send_error(nc, 503, NULL);
					return 0;
				}
				
				snprintf(shead, sizeof(shead), "Set-Cookie: %s=%" INT64_X_FMT "; path=/", HTTP_SESSION_COOKIE_NAME, s->id);
				mg_http_send_redirect(nc, 302, mg_mk_str("/"), mg_mk_str(shead));
				return 0;
			}
		}
	}

	s = get_http_session(hm);
	if (!s) {
		mg_http_send_redirect(nc, 302, mg_mk_str("/login.html"), mg_mk_str(""));
		return 0;
	}
	
	return 1;
}

/* Creates a new tty session */
static struct tty_session *create_tty_session(const char *mac, struct mg_connection *nc)
{
	unsigned char digest[20];
	struct tty_session *s = calloc(1, sizeof(struct tty_session));
	if (!s)
		return NULL;
	
	s->nc = nc;
	
	if (mac) {
		memcpy(s->mac, mac, 12);
	
		/* Create an ID by putting various volatiles into a pot and stirring. */
		cs_sha1_ctx ctx;
		cs_sha1_init(&ctx);
		cs_sha1_update(&ctx, (const unsigned char *)s->mac, 12);
		cs_sha1_update(&ctx, (const unsigned char *)s, sizeof(*s));
		
		cs_sha1_final(digest, &ctx);
		s->id = *((uint64_t *)digest);
	}
	list_add(&s->node, &tty_sessions);	
	return s;
}

static void destroy_tty_session(struct tty_session *s)
{
	list_del(&s->node);
	free(s);
}

static struct tty_session *find_tty_session_by_websocket(struct mg_connection *nc)
{
	struct tty_session *s;
	list_for_each_entry(s, &tty_sessions, node) {
		if (s->nc == nc)
			return s;
	}
	
	return NULL;
}

static struct tty_session *find_tty_session_by_sid(uint64_t sid)
{
	struct tty_session *s;
	list_for_each_entry(s, &tty_sessions, node) {
		if (s->id == sid)
			return s;
	}
	
	return NULL;
}

static struct device *find_device_by_mac(const char *mac)
{
	struct device *d;
	list_for_each_entry(d, &devices_list, node) {
		if (!memcmp(d->mac, mac, 12))
			return d;
	}
	
	return NULL;
}

static void http_ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	switch (ev) {
	case MG_EV_HTTP_REQUEST: {
			struct http_message *hm = (struct http_message *)ev_data;
			
			if (!http_login(nc, hm))
				return;
			
			if (!mg_vcmp(&hm->uri, "/list")) {
				struct device *d;
				
				mg_send_head(nc, 200, -1, NULL);
				mg_send_http_chunk(nc, "[", 1);
				
				list_for_each_entry(d, &devices_list, node) {
					mg_send_http_chunk(nc, "\"", 1);
					mg_send_http_chunk(nc, d->mac, 12);
					mg_send_http_chunk(nc, "\",", 2);
				}
				
				mg_send_http_chunk(nc, "\"\"]", 3);
				mg_send_http_chunk(nc, NULL, 0);
				return;
			}
			
			mg_serve_http(nc, hm, http_server_opts); /* Serve static content */
			break;
		}
	case MG_EV_WEBSOCKET_HANDSHAKE_REQUEST: {
			struct http_message *hm = (struct http_message *)ev_data;
			char mac[13];
			if (mg_get_http_var(&hm->query_string, "mac", mac, sizeof(mac)) != 12)
				create_tty_session(NULL, nc);
			else
				create_tty_session(mac, nc);
			break;
		}
	case MG_EV_WEBSOCKET_HANDSHAKE_DONE: {
			char data[128] = "{\"mt\":\"connect\", \"status\": \"ok\"}";
			struct device *d = NULL;
			struct tty_session *s = find_tty_session_by_websocket(nc);
			if (!s)
				strncpy(data, "{\"mt\":\"connect\", \"status\": \"error\", \"reason\":\"Unknown error\"}", sizeof(data));
			else if (!s->mac)
				strncpy(data, "{\"mt\":\"connect\", \"status\": \"error\", \"reason\":\"Invalid macaddress\"}", sizeof(data));
			else if (!(d = find_device_by_mac(s->mac)))
				strncpy(data, "{\"mt\":\"connect\", \"status\": \"error\", \"reason\":\"Device is offline\"}", sizeof(data));
			
			mg_send_websocket_frame(nc, WEBSOCKET_OP_TEXT, data, strlen(data));
			
			if (d && d->nc) {
				struct mg_mqtt_topic_expression topic_expr[3];
				char topic[128];
				
				snprintf(topic, sizeof(topic), "xterminal/touser/data/%"INT64_X_FMT, s->id);
				topic_expr[0].topic = strdup(topic);
				topic_expr[0].qos = 0;
				
				snprintf(topic, sizeof(topic), "xterminal/touser/disconnect/%"INT64_X_FMT, s->id);
				topic_expr[1].topic = strdup(topic);
				topic_expr[1].qos = 0;
				
				snprintf(topic, sizeof(topic), "xterminal/uploadfilefinish/%"INT64_X_FMT, s->id);
				topic_expr[2].topic = strdup(topic);
				topic_expr[2].qos = 0;
			
				mg_mqtt_subscribe(d->nc, topic_expr, 3, 0);
				free((void *)topic_expr[0].topic);
				free((void *)topic_expr[1].topic);
				free((void *)topic_expr[2].topic);
				
				snprintf(topic, sizeof(topic), "xterminal/connect/%s/%"INT64_X_FMT, d->mac, s->id);
				mg_mqtt_publish(d->nc, topic, 0, 0, NULL, 0);
				
				snprintf(s->topic_data, sizeof(s->topic_data), "xterminal/todev/data/%"INT64_X_FMT, s->id);
				snprintf(s->topic_disconnect, sizeof(s->topic_disconnect), "xterminal/todev/disconnect/%"INT64_X_FMT, s->id);
			}
			break;
		}
	case MG_EV_WEBSOCKET_FRAME: {
			struct websocket_message *wm = (struct websocket_message *)ev_data;
			struct device *d;
			struct tty_session *s = find_tty_session_by_websocket(nc);
			if (!s) {
				mg_send_websocket_frame(nc, WEBSOCKET_OP_CLOSE, NULL, 0);
				return;
			}
			
			d = find_device_by_mac(s->mac);
			if (!d) {
				mg_send_websocket_frame(nc, WEBSOCKET_OP_CLOSE, NULL, 0);
				return;
			}
			
			if (wm->flags & WEBSOCKET_OP_TEXT) {
			} else if (wm->flags & WEBSOCKET_OP_BINARY) {
				mg_mqtt_publish(d->nc, s->topic_data, 0, 0, wm->data, wm->size);
			}
			
			break;
		}
	case MG_EV_CLOSE: {
			if (nc->flags & MG_F_IS_WEBSOCKET) {
				struct tty_session *s = find_tty_session_by_websocket(nc);
				if (s) {
					struct device *d = find_device_by_mac(s->mac);
					if (d)
						mg_mqtt_publish(d->nc, s->topic_disconnect, 0, 0, NULL, 0);
					destroy_tty_session(s);
					
					printf("session close\n");
				}
			}
			break;
		}
	}
}

static void http_session_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct http_session *s, *tmp;
	double threshold = mg_time() - HTTP_SESSION_TTL;
	
	list_for_each_entry_safe(s, tmp, &http_sessions, node) {
		if (s->id && s->last_used < threshold) {
			destroy_http_session(s);
		}
	}
}

static void update_device(const char *mac, struct mg_connection *nc)
{
	struct device *d;
	
	list_for_each_entry(d, &devices_list, node) {
		if (!memcmp(d->mac, mac, 12)) {
			d->last_active = mg_time();
			return;
		}
	}
	
	d = calloc(1, sizeof(struct device));
	if (!d)
		return;
	
	d->last_active = mg_time();
	d->nc = nc;
	memcpy(d->mac, mac, 12);
	list_add(&d->node, &devices_list);
	
	syslog(LOG_INFO, "new dev:[%s]", d->mac);
}

static void device_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct device *d, *tmp;
	double threshold = mg_time() - DEVICE_TTL;
	
	list_for_each_entry_safe(d, tmp, &devices_list, node) {
		if (d->last_active < threshold) {
			syslog(LOG_INFO, "dev [%s] offline", d->mac);
			list_del(&d->node);
			free(d);
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
			struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
			struct mg_mqtt_topic_expression topic_expr = {
				.topic = "xterminal/heartbeat/+"
			};
			
			if (msg->connack_ret_code != MG_EV_MQTT_CONNACK_ACCEPTED) {
				syslog(LOG_ERR, "Got mqtt connection error: %d", msg->connack_ret_code);
				return;
			}
			
			mg_mqtt_subscribe(nc, &topic_expr, 1, 0);
			break;
		}

	case MG_EV_MQTT_PUBLISH: {
			struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
			char ssid[21] = "";
			struct tty_session *s;
			
			//printf("Got incoming message %.*s: %.*s\n", (int) msg->topic.len, msg->topic.p, (int) msg->payload.len, msg->payload.p);
			
			if (memmem(msg->topic.p + 9, msg->topic.len - 9, "heartbeat", strlen("heartbeat"))) {
				update_device(msg->topic.p + 11 + strlen("heartbeat"), nc);
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "touser/data", strlen("touser/data"))) {
				memcpy(ssid, msg->topic.p + 11 + strlen("touser/data"), 16);
				s = find_tty_session_by_sid(strtoull(ssid, NULL, 16));
				if (s)
					mg_send_websocket_frame(s->nc, WEBSOCKET_OP_BINARY, msg->payload.p, msg->payload.len);
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "touser/disconnect", strlen("touser/disconnect"))) {
				memcpy(ssid, msg->topic.p + 11 + strlen("touser/disconnect"), 16);
				s = find_tty_session_by_sid(strtoull(ssid, NULL, 16));
				if (s) {
					mg_send_websocket_frame(s->nc, WEBSOCKET_OP_CLOSE, NULL, 0);
					destroy_tty_session(s);
				}
			}
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
	int http_auth_cnt = 1;
	struct mg_bind_opts bind_opts;
	static ev_timer http_session_timer;
	static ev_timer device_timer;
	
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
			else if (!strcmp(longopts[option_index].name, "http-auth")) {
				if (http_auth_cnt < MAX_HTTP_AUTH)
					http_auth[http_auth_cnt++] = optarg;
			} else if (!strcmp(longopts[option_index].name, "ssl-cert"))
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
	
	ev_timer_init(&http_session_timer, http_session_timer_cb, 5, 5);
	ev_timer_start(loop, &http_session_timer);
	
	ev_timer_init(&device_timer, device_timer_cb, 5, 5);
	ev_timer_start(loop, &device_timer);
	
	ev_run(loop, 0);

err:
	mg_mgr_free(&mgr);

	return 0;
}