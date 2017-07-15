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
					
static char broker[128];
static char dev_id[13];
static char heartbeat_topic[128];
static ev_timer heartbeat_timer;

static void heartbeat_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct mg_connection *nc = (struct mg_connection *)w->data;
	mg_mqtt_publish(nc, heartbeat_topic, 0, 0, NULL, 0);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	switch (ev) {
	case MG_EV_CONNECT: {
			struct mg_send_mqtt_handshake_opts opts;
			int err = *(int *)ev_data;
			
			if (err) {
				syslog(LOG_ERR, "connect() failed: %s", strerror(err));
				return;
			}
			
			memset(&opts, 0, sizeof(opts));
			opts.flags |= MG_MQTT_CLEAN_SESSION;

			mg_set_protocol_mqtt(nc);
			mg_send_mqtt_handshake_opt(nc, dev_id, opts);
			break;
		}

	case MG_EV_MQTT_CONNACK: {
			struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
			struct mg_mqtt_topic_expression topic_expr;
			char topic[128];
			
			if (msg->connack_ret_code != MG_EV_MQTT_CONNACK_ACCEPTED) {
				syslog(LOG_ERR, "Got mqtt connection error: %d", msg->connack_ret_code);
				return;
			}
			
			snprintf(topic, sizeof(topic), "xterminal/connect/%s/+", dev_id);
			topic_expr.topic = topic;
			mg_mqtt_subscribe(nc, &topic_expr, 1, 0);

			ev_timer_start(nc->mgr->loop, &heartbeat_timer);
			break;
		}

	case MG_EV_MQTT_PUBLISH: {
			struct mg_mqtt_message *msg = (struct mg_mqtt_message *)ev_data;
			static char id[11];
			
			if (memmem(msg->topic.p + 9, msg->topic.len - 9, "connect", strlen("connect"))) {
				memcpy(id, msg->topic.p + 9, 10);
				printf("id = [%s]\n", id);
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "todev/data", strlen("todev/data"))) {
				
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "todev/disconnect", strlen("todev/disconnect"))) {
				
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "uploadfile", strlen("uploadfile"))) {
				
			}
			
			break;
		}
	}
}

static char *get_dev_id(const char *ifname, char *out)
{
	char path[64];
	char address[18] = "";
	FILE *fp;
	int i, j, ret = -1;
	
	assert(out);
	snprintf(path, sizeof(path), "/sys/class/net/%s/address", ifname);
	
	fp = fopen(path, "r");
	if (!fp) {
		syslog(LOG_ERR, "Can't open %s", path);
		return NULL;
	}
	
	ret = fread(address, 17, 1, fp);
	if (ret < 0) {
		syslog(LOG_ERR, "Can't read devid in %s", path);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	
	for (i = 0, j = 0; i < 17; i += 3, j += 2) {
		
		out[j] = toupper(address[i]);
		out[j + 1] = toupper(address[i + 1]);
	}
	
	return out;
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	ev_break(loop, EVBREAK_ALL);
}

static  void usage(const char *program)
{
	printf("Usage:%s [options]\n", program);
	printf("     -d              Log to stderr\n"
		"     -i              default is eth0\n"
        "     --mqtt-port     default is 1883\n"
        "     --mqtt-host     default is localhost\n");
	
	exit(0);
}

int main(int argc, char *argv[])
{
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal sig_watcher;
	int log_to_stderr = 0;
	const char *ifname = "eth0";
	const char *mqtt_port = "1883", *mqtt_host = "localhost";
	struct mg_mgr mgr;
	struct mg_connection *nc;
	struct option longopts[] = {
		{"help",  no_argument, NULL, 'h'},
		{"mqtt-port", required_argument, NULL, 0},
		{"mqtt-host", required_argument, NULL, 0},
		{0, 0, 0, 0}
	};
	
	while (1) {
		int c, option_index;
		c = getopt_long(argc, argv, "hdi:", longopts, &option_index);
		if (c == -1)
			break;
		
		switch (c) {
		case 'd':
			log_to_stderr = 1;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 0:
			if (!strcmp(longopts[option_index].name, "mqtt-port"))
				mqtt_port = optarg;
			else if (!strcmp(longopts[option_index].name, "mqtt-host"))
				mqtt_host = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	
	if (log_to_stderr)
		openlog("xterminal device", LOG_ODELAY | LOG_PERROR, LOG_USER);
	else
		openlog("xterminal device", LOG_ODELAY, LOG_USER);
	
	snprintf(broker, sizeof(broker), "%s:%s", mqtt_host, mqtt_port);
	
	mg_mgr_init(&mgr, NULL, loop);
	
	if (!get_dev_id(ifname, dev_id))
		goto err;
	
	syslog(LOG_INFO, "Fetch dev id:[%s]", dev_id);
	
	ev_signal_init(&sig_watcher, signal_cb, SIGINT);
	ev_signal_start(loop, &sig_watcher);

	nc = mg_connect(&mgr, broker, ev_handler);
	if (!nc) {
		syslog(LOG_ERR, "mg_connect(%s) failed", broker);
		goto err;
	}
	
	ev_timer_init(&heartbeat_timer, heartbeat_timer_cb, 0.1, 10);
	heartbeat_timer.data = nc;
	snprintf(heartbeat_topic, sizeof(heartbeat_topic), "xterminal/heartbeat/%s", dev_id);
	
	ev_run(loop, 0);

err:
	mg_mgr_free(&mgr);

	return 0;
}