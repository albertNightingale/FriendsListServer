/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void doit(int fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void serve_request(int fd, dictionary_t *query, dictionary_t *header, char *uri);

static dictionary_t *friendGraph; 

int main(int argc, char **argv)
{
	int listenfd, connfd;
	char hostname[MAXLINE], port[MAXLINE];
	socklen_t clientlen;
	struct sockaddr_storage clientaddr;

	/* Check command line args */
	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <port>\n", argv[0]);
		exit(1);
	}

	listenfd = Open_listenfd(argv[1]);

	/* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
	exit_on_error(0);

	/* Also, don't stop on broken connections: */
	Signal(SIGPIPE, SIG_IGN);

	friendGraph = make_dictionary(COMPARE_CASE_INSENS, free); // initialize the friend graph

	while (1)
	{
		clientlen = sizeof(clientaddr);
		connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
		if (connfd >= 0)
		{
			Getnameinfo((SA *)&clientaddr, clientlen, hostname, MAXLINE,
						port, MAXLINE, 0);
			printf("Accepted connection from (%s, %s)\n", hostname, port);
			doit(connfd);
			Close(connfd);
		}
	}
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd)
{
	char buf[MAXLINE], *method, *uri, *version;
	rio_t rio;
	dictionary_t *headers, *query;

	/* Read request line and headers */
	Rio_readinitb(&rio, fd);
	if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
		return;
	printf("******* start of handling this request ******** \n");
	printf("request content (header and body): %s \n", buf);

	unsigned char parseSuccessful = parse_request_line(buf, &method, &uri, &version); // split buffer to method, uri, and version
	if (!parseSuccessful)
	{
		clienterror(fd, method, "400", "Bad Request", "Friendlist did not recognize the request \n");
	}
	else
	{
		unsigned char isPost = !strcasecmp(method, "POST");
		unsigned char isGet = !strcasecmp(method, "GET");
		if (strcasecmp(version, "HTTP/1.0") && strcasecmp(version, "HTTP/1.1")) // not version 1.0 or 1.1
		{
			clienterror(fd, version, "501", "Not Implemented", "Friendlist does not implement that version \n");
		}
		else if (!isGet && !isPost) // not method GET or POST
		{
			clienterror(fd, method, "501", "Not Implemented", "Friendlist does not implement that method \n");
		}
		else
		{
			headers = read_requesthdrs(&rio);

			/* Parse all query arguments into a dictionary */
			query = make_dictionary(COMPARE_CASE_SENS, free);
			parse_uriquery(uri, query); // some queries will be in the URI

			if (isPost)
			{ // for POST method, some queries will be in the body
				read_postquery(&rio, headers, query);
			}

			/* For debugging, print the dictionary */
			printf("******* header is printed ******** \n");
			print_stringdictionary(headers);
			printf("******* query is printed ******** \n");
			print_stringdictionary(query);

			/* 
			You'll want to handle different queries here,
			but the intial implementation always returns
			nothing: 
			*/
			serve_request(fd, query, headers, uri);
			printf("******* end of handling this request ******** \n\n\n");

			/* Clean up */
			free_dictionary(query);
			free_dictionary(headers);
		}

		/* Clean up status line */
		free(method);
		free(uri);
		free(version);
	}
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp)
{
	char buf[MAXLINE];
	dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

	Rio_readlineb(rp, buf, MAXLINE);
	printf("%s", buf);
	while (strcmp(buf, "\r\n"))
	{
		Rio_readlineb(rp, buf, MAXLINE);
		printf("%s", buf);
		parse_header_line(buf, d);
	}

	return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest)
{
	char *len_str, *type, *buffer;
	int len;

	len_str = dictionary_get(headers, "Content-Length");
	len = (len_str ? atoi(len_str) : 0);

	type = dictionary_get(headers, "Content-Type");

	buffer = malloc(len + 1);
	Rio_readnb(rp, buffer, len);
	buffer[len] = 0;

	if (!strcasecmp(type, "application/x-www-form-urlencoded"))
	{
		parse_query(buffer, dest);
	}

	free(buffer);
}

static char *ok_header(size_t len, const char *content_type)
{
	char *len_str, *header;

	header = append_strings("HTTP/1.0 200 OK\r\n",
							"Server: Friendlist Web Server\r\n",
							"Connection: close\r\n",
							"Content-length: ", len_str = to_string(len), "\r\n",
							"Content-type: ", content_type, "\r\n\r\n",
							NULL);
	free(len_str);

	return header;
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, dictionary_t *query, dictionary_t *header, char *uri)
{
	char *path = split_string(uri, '/')[1];
	printf("path is parsed out\n");
	if (starts_with("friends?", path)) {
		char *user = dictionary_get(query, "user");
		if (!user) {
			clienterror(fd, "user query not found for friends", "404", "BAD", "BAD");
			return;
		}
		char *friends = dictionary_get(friendGraph, user);
		if (!friends) {  // if doesn't exist in the dictionary
			// insert to the dictionary
			friends = ""; // set to empty string
			dictionary_set(friendGraph, user, "");
		}
		unsigned char isEmpty = !strcmp(friends, "");
		if (isEmpty) {
			prinf("no response is needed, technically\n");
		}
	}
	else if (starts_with("befriend?", path)) {

	}
	else if (starts_with("unfriend?", path)) {

	}
	else if (starts_with("introduce?", path)) {

	}
	else {
		printf("path is not valid %s \n", path);
	}

	size_t len;
	char *body, *resHeader;

	body = strdup("alice\nbob");

	len = strlen(body);

	/* Send response headers to client */
	resHeader = ok_header(len, "text/html; charset=utf-8");
	Rio_writen(fd, resHeader, strlen(resHeader));
	printf("Response headers:\n");
	printf("%s", resHeader);

	free(resHeader);

	/* Send response body to client */
	Rio_writen(fd, body, len);

	free(body);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum,
				 char *shortmsg, char *longmsg)
{
	size_t len;
	char *header, *body, *len_str;

	body = append_strings("<html><title>Friendlist Error</title>",
						  "<body bgcolor="
						  "ffffff"
						  ">\r\n",
						  errnum, " ", shortmsg,
						  "<p>", longmsg, ": ", cause,
						  "<hr><em>Friendlist Server</em>\r\n",
						  NULL);
	len = strlen(body);

	/* Print the HTTP response */
	header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
							"Content-type: text/html; charset=utf-8\r\n",
							"Content-length: ", len_str = to_string(len), "\r\n\r\n",
							NULL);
	free(len_str);

	Rio_writen(fd, header, strlen(header));
	Rio_writen(fd, body, len);

	free(header);
	free(body);
}

static void print_stringdictionary(dictionary_t *d)
{
	int i, count;

	count = dictionary_count(d);
	for (i = 0; i < count; i++)
	{
		printf("%s=%s\n",
			   dictionary_key(d, i),
			   (const char *)dictionary_value(d, i));
	}
	printf("\n");
}
