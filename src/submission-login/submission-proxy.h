#ifndef SUBMISSION_PROXY_H
#define SUBMISSION_PROXY_H

#include "login-proxy.h"
#include "smtp-dovecot.h"

/* Classify a backend AUTH failure reply that closes the connection (421).
   Only Dovecot's own connection-limit reply (421 4.7.900) means that the
   user's connection limit (mail_max_userip_connections) was reached. A
   generic 421 4.7.0 reply from a non-Dovecot backend may indicate throttling
   or another temporary service condition, so it must keep the normal
   already-replied auth failure behavior (including the reconnect policy). */
static inline enum login_proxy_failure_type
submission_proxy_auth_failure_type(unsigned int status, const char *enh_code)
{
	return smtp_reply_code_is_conn_limit(status, enh_code) ?
		LOGIN_PROXY_FAILURE_TYPE_AUTH_LIMIT_REACHED_REPLIED :
		LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED;
}

void submission_proxy_reset(struct client *client);
int submission_proxy_parse_line(struct client *client, const char *line);

void submission_proxy_failed(struct client *client,
			     enum login_proxy_failure_type type,
			     const char *reason, bool reconnecting);
const char *submission_proxy_get_state(struct client *client);

#endif
