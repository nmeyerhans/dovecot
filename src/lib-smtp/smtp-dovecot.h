#ifndef SMTP_DOVECOT
#define SMTP_DOVECOT

#include "smtp-reply.h"

#define SMTP_PROXY_REDIRECT_CODE         550
#define SMTP_PROXY_REDIRECT_ENH_CODE     SMTP_REPLY_ENH_CODE(5, 2, 900)
#define SMTP_PROXY_REDIRECT_ENH_CODE_STR "5.2.900"

/* Dovecot-specific response for "too many connections from this user+IP".
   421 means "service shutting down, closing transmission channel"
   (RFC 5321, Section 4.2.1), which tells the client that retrying on this
   same connection is pointless. The detail part 900 of the enhanced status
   code is in the private/implementation-specific range (like the redirect
   code above), so that a proxy can recognize Dovecot's connection limit
   response and distinguish it from a generic 421 4.7.0 reply emitted by
   non-Dovecot backends for other temporary conditions. */
#define SMTP_PROXY_CONN_LIMIT_CODE         421
#define SMTP_PROXY_CONN_LIMIT_ENH_CODE     SMTP_REPLY_ENH_CODE(4, 7, 900)
#define SMTP_PROXY_CONN_LIMIT_ENH_CODE_STR "4.7.900"

struct smtp_reply;
struct smtp_server_cmd_ctx;
struct smtp_server_recipient;

struct smtp_proxy_redirect {
	const char *username;
	const char *host;
	struct ip_addr host_ip;
	in_port_t port;
};

bool smtp_reply_code_is_proxy_redirect(unsigned int code, const char *enh_code);
bool smtp_reply_is_proxy_redirect(const struct smtp_reply *reply);

bool smtp_reply_code_is_conn_limit(unsigned int code, const char *enh_code);
bool smtp_reply_is_conn_limit(const struct smtp_reply *reply);

int smtp_proxy_redirect_parse(const char *resp, const char **destuser_r,
			      const char **host_r, struct ip_addr *ip_r,
			      in_port_t *port_r, const char **error_r);

void smtp_server_reply_redirect(struct smtp_server_cmd_ctx *cmd,
				in_port_t default_port,
				const struct smtp_proxy_redirect *predir);
void smtp_server_recipient_reply_redirect(
	struct smtp_server_recipient *rcpt, in_port_t default_port,
	const struct smtp_proxy_redirect *predir);

#endif
