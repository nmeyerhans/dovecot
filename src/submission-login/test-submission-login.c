/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "test-common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "net.h"
#include "settings-consts.h"
#include "login-proxy.h"
#include "smtp-server.h"
#include "smtp-dovecot.h"
#include "submission-proxy.h"

/*
 * Backend AUTH failure reply classification
 */

static void test_proxy_auth_failure_type(void)
{
	test_begin("submission proxy backend auth failure type");

	/* Dovecot's connection-limit reply must suppress reconnecting */
	test_assert(submission_proxy_auth_failure_type(
			SMTP_PROXY_CONN_LIMIT_CODE,
			SMTP_PROXY_CONN_LIMIT_ENH_CODE_STR) ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_LIMIT_REACHED_REPLIED);

	/* A generic 421 4.7.0 reply from a non-Dovecot backend is just a
	   normal already-replied auth failure, which allows reconnecting */
	test_assert(submission_proxy_auth_failure_type(421, "4.7.0") ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED);
	test_assert(submission_proxy_auth_failure_type(421, "4.3.2") ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED);
	test_assert(submission_proxy_auth_failure_type(421, NULL) ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED);

	/* The enhanced code alone is not enough */
	test_assert(submission_proxy_auth_failure_type(
			454, SMTP_PROXY_CONN_LIMIT_ENH_CODE_STR) ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED);
	test_assert(submission_proxy_auth_failure_type(535, "5.7.8") ==
		    LOGIN_PROXY_FAILURE_TYPE_AUTH_REPLIED);

	test_end();
}

static void test_reply_conn_limit(void)
{
	struct smtp_reply reply;

	test_begin("smtp connection limit reply");

	i_zero(&reply);
	reply.status = SMTP_PROXY_CONN_LIMIT_CODE;
	reply.enhanced_code = SMTP_PROXY_CONN_LIMIT_ENH_CODE;
	test_assert(smtp_reply_is_conn_limit(&reply));

	reply.enhanced_code = SMTP_REPLY_ENH_CODE(4, 7, 0);
	test_assert(!smtp_reply_is_conn_limit(&reply));

	test_end();
}

/*
 * Client teardown ordering
 *
 * This mirrors the ownership rules implemented by submission-login's
 * client.c: the login client closes the smtp-server connection, unless the
 * smtp-server connection is itself running its disconnect cascade. In the
 * latter case the connection pointer must survive until the conn_free
 * callback, which is what calls client_destroy().
 */

struct test_client {
	struct smtp_server_connection *conn;

	unsigned int disconnect_callbacks;
	unsigned int destroy_count;
};

/* Mirrors submission_client_disconnect() in client.c */
static void
test_client_disconnect(struct test_client *client, const char *reason)
{
	if (client->conn != NULL &&
	    !smtp_server_connection_is_disconnected(client->conn))
		smtp_server_connection_close(&client->conn, reason);
}

static void test_conn_disconnect(void *context, const char *reason)
{
	struct test_client *client = context;

	client->disconnect_callbacks++;
	if (client->conn != NULL) {
		/* The connection is already in its disconnect cascade here,
		   but it is only marked closed when the teardown was entered
		   through smtp_server_connection_close(). */
		test_assert(smtp_server_connection_is_disconnected(
			client->conn));
	}
	test_client_disconnect(client, reason);
}

static void test_conn_free(void *context)
{
	struct test_client *client = context;

	if (client->conn == NULL)
		return;
	client->conn = NULL;
	/* This is where client_destroy() is called */
	client->destroy_count++;
}

static const struct smtp_server_callbacks test_smtp_callbacks = {
	.conn_disconnect = test_conn_disconnect,
	.conn_free = test_conn_free,
};

static struct smtp_server_connection *
test_connection_create(struct smtp_server *server, struct test_client *client,
		       int fds[2])
{
	struct smtp_server_connection *conn;
	struct istream *input;
	struct ostream *output;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
		i_fatal("socketpair() failed: %m");

	input = i_stream_create_fd(fds[0], 1024);
	output = o_stream_create_fd(fds[0], 1024);
	o_stream_set_no_error_handling(output, TRUE);

	i_zero(client);
	conn = smtp_server_connection_create_from_streams(
		server, input, output, NULL, 0, NULL, 0, NULL,
		&test_smtp_callbacks, client);
	client->conn = conn;

	i_stream_unref(&input);
	o_stream_unref(&output);
	return conn;
}

static void test_client_teardown(void)
{
	struct smtp_server_settings smtp_set;
	struct smtp_server *server;
	struct smtp_server_connection *conn;
	struct test_client client;
	struct ioloop *ioloop;
	int fds[2];

	ioloop = io_loop_create();

	i_zero(&smtp_set);
	smtp_set.max_recipients = SET_UINT_UNLIMITED;
	server = smtp_server_init(&smtp_set);

	test_begin("submission client teardown via smtp connection");

	/* The smtp-server connection owns the teardown: conn_disconnect is
	   called before the connection is marked closed, so the client must
	   not close (and thereby clear) the connection itself. */
	conn = test_connection_create(server, &client, fds);
	smtp_server_connection_unref(&conn);

	test_assert(client.disconnect_callbacks == 1);
	test_assert(client.conn == NULL);
	test_assert(client.destroy_count == 1);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);
	test_end();

	test_begin("submission client teardown via login client");

	/* Generic login-client teardown: the client closes the smtp-server
	   connection, and client_destroy() is not called from conn_free()
	   (the caller is already destroying the client). */
	(void)test_connection_create(server, &client, fds);
	test_client_disconnect(&client, "Disconnected");

	test_assert(client.disconnect_callbacks == 1);
	test_assert(client.conn == NULL);
	test_assert(client.destroy_count == 0);

	i_close_fd(&fds[0]);
	i_close_fd(&fds[1]);
	test_end();

	smtp_server_deinit(&server);
	io_loop_destroy(&ioloop);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_proxy_auth_failure_type,
		test_reply_conn_limit,
		test_client_teardown,
		NULL
	};

	return test_run(test_functions);
}
