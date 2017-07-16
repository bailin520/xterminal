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
					
static char broker[128];
static char dev_id[13];
static char heartbeat_topic[128];
static ev_timer heartbeat_timer;

LIST_HEAD(tty_sessions); /* tty_session list */

struct tty_session {
	pid_t pid;
	int pty;
	uint64_t sid;
	struct mg_connection *nc;
	ev_io iow;
	ev_io ior;
	struct mbuf send_mbuf;
	char topic_data[128];
	char topic_disconnect[128];
	char topic_upfile[128];
	struct list_head node;
};

struct upfile_param {
	struct tty_session *s;
	char *filename;
};

static void wait_child(pid_t pid)
{
	int status = 0;
	waitpid(pid, &status, 0);
#if 0		
	if (WIFEXITED(status))
		printf("child process %d exited:%d\n", pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		printf("child process %d killed:%d\n", pid, WTERMSIG(status));
	else if (WIFSTOPPED(status))
		printf("child process %d stopped:%d\n", pid, WSTOPSIG(status));
#endif	
}

static void ev_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	char buf[1024];
	int len;
	struct tty_session *s = (struct tty_session *)w->data;
	
	len = read(w->fd, buf, sizeof(buf));
	if (len > 0) {
		mg_mqtt_publish(s->nc, s->topic_data, 0, 0, buf, len);
	} else {
		ev_io_stop(loop, w);
		wait_child(s->pid);
		mg_mqtt_publish(s->nc, s->topic_disconnect, 0, 0, NULL, 0);
	}
}

static struct tty_session *create_tty_session(struct mg_connection *nc, uint64_t sid)
{
	int pty;
	pid_t pid;
	struct tty_session *s;
	struct mg_mqtt_topic_expression topic_expr[3];
	char topic[128];
				
	s = calloc(1, sizeof(struct tty_session));
	if (!s)
		return NULL;
	
	pid = forkpty(&pty, NULL, NULL, NULL);
	if (pid == 0)
		execl("/bin/login", "/bin/login", NULL);
	
	s->sid = sid;
	s->pid = pid;
	s->pty = pty;
	s->nc = nc;
	list_add(&s->node, &tty_sessions);
	
	snprintf(topic, sizeof(topic), "xterminal/todev/data/%"INT64_X_FMT, s->sid);
	topic_expr[0].topic = strdup(topic);
	topic_expr[0].qos = 0;
	
	snprintf(topic, sizeof(topic), "xterminal/todev/disconnect/%"INT64_X_FMT, s->sid);
	topic_expr[1].topic = strdup(topic);
	topic_expr[1].qos = 0;
	
	snprintf(topic, sizeof(topic), "xterminal/uploadfile/%"INT64_X_FMT, s->sid);
	topic_expr[2].topic = strdup(topic);
	topic_expr[2].qos = 0;
	
	mg_mqtt_subscribe(nc, topic_expr, 3, 0);
	free((void *)topic_expr[0].topic);
	free((void *)topic_expr[1].topic);
	free((void *)topic_expr[2].topic);
	
	snprintf(s->topic_data, sizeof(s->topic_data), "xterminal/touser/data/%"INT64_X_FMT, s->sid);
	snprintf(s->topic_disconnect, sizeof(s->topic_disconnect), "xterminal/touser/disconnect/%"INT64_X_FMT, s->sid);
	snprintf(s->topic_upfile, sizeof(s->topic_upfile), "xterminal/uploadfilefinish/%"INT64_X_FMT, s->sid);
	
	ev_io_init(&s->ior, ev_read_cb, s->pty, EV_READ);
	s->ior.data = s;
	ev_io_start(nc->mgr->loop, &s->ior);
	return s;
}

static struct tty_session *find_tty_session_by_sid(uint64_t sid)
{
	struct tty_session *s;
	list_for_each_entry(s, &tty_sessions, node) {
		if (s->sid == sid)
			return s;
	}
	
	return NULL;
}

static void destroy_tty_session(struct ev_loop *loop, struct tty_session *s)
{	
	ev_io_stop(loop, &s->ior);	
	kill(s->pid, SIGKILL);
	wait_child(s->pid);
	list_del(&s->node);
	free(s);
}

static void heartbeat_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct mg_connection *nc = (struct mg_connection *)w->data;
	mg_mqtt_publish(nc, heartbeat_topic, 0, 0, NULL, 0);
}

static void http_ev_handler(struct mg_connection *nc, int ev, void *ev_data)
{
	switch (ev) {
	case MG_EV_HTTP_REPLY: {
			struct http_message *hm = (struct http_message *)ev_data;
			int len, fd;
			struct upfile_param *param = (struct upfile_param *)nc->user_data;
			struct tty_session *s = param->s;
			
			fd = open(param->filename, O_WRONLY | O_CREAT, 0644);
			if (fd > 0) {
				while (1) {
					len = write(fd, hm->body.p, hm->body.len);
					if (len < 0) {
						syslog(LOG_ERR, "write %s failed:%s", param->filename, strerror(errno));
						break;
					}
					
					if (len == hm->body.len)
						break;
					
					hm->body.len -= len;
					hm->body.p += len;
				}
				close(fd);
			} else {
				syslog(LOG_ERR, "open %s failed:%s", param->filename, strerror(errno));
			}
			
			nc->flags |= MG_F_CLOSE_IMMEDIATELY;
			mg_mqtt_publish(s->nc, s->topic_upfile, 0, 0, NULL, 0);
			free(param->filename);
			free(param);
			break;
		}
	}
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
			char ssid[21] = "";
			uint64_t sid;
			struct tty_session *s;
			
			//printf("Got incoming message %.*s: %.*s\n", (int) msg->topic.len, msg->topic.p, (int) msg->payload.len, msg->payload.p);
			
			if (memmem(msg->topic.p + 9, msg->topic.len - 9, "todev/disconnect", strlen("todev/disconnect"))) {
				memcpy(ssid, msg->topic.p + 27, 16);
				sid = strtoull(ssid, NULL, 16);
				s = find_tty_session_by_sid(sid);
				if (s)
					destroy_tty_session(nc->mgr->loop, s);
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "connect", strlen("connect"))) {
				memcpy(ssid, msg->topic.p + 31, 16);
				sid = strtoull(ssid, NULL, 16);
				create_tty_session(nc, sid);
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "todev/data", strlen("todev/data"))) {
				memcpy(ssid, msg->topic.p + 21, 16);
				sid = strtoull(ssid, NULL, 16);
				s = find_tty_session_by_sid(sid);
				if (s) {
					int ret = write(s->pty, msg->payload.p, msg->payload.len);
					if (ret < 0) {
						syslog(LOG_ERR, "write error:%s", strerror(errno));
					}
				}
			} else if (memmem(msg->topic.p + 9, msg->topic.len - 9, "uploadfile", strlen("uploadfile"))) {
				char *p, url[128] = "";
				struct mg_connection *ncc;
				
				memcpy(ssid, msg->topic.p + 21, 16);
				sid = strtoull(ssid, NULL, 16);
				s = find_tty_session_by_sid(sid);
				if (!s)
					return;

				p = memchr(msg->payload.p, ' ', msg->payload.len);
				if (!p)
					return;
				*p = 0;
				strcpy(url, msg->payload.p);
				strcat(url, "/");
				snprintf(url + strlen(url), sizeof(url) - strlen(url), "%.*s", (int)(msg->payload.len - strlen(url)), p + 1);
				ncc = mg_connect_http(nc->mgr, http_ev_handler, url, NULL, NULL);
				if (ncc) {
					struct upfile_param *param = malloc(sizeof(struct upfile_param));
					char *filename = calloc(1, msg->payload.len + msg->payload.p - p + 5);
					memcpy(filename, "/tmp/", 5);
					memcpy(filename + 5, p + 1, msg->payload.len + msg->payload.p - p - 1);
					
					param->filename = filename;
					param->s = s;
					ncc->user_data = param;
				}
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