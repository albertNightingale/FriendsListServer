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
static void handleGetFriends(const char *user, char **body);
static void handleBeFriend(const char *user, const char *new_friends, char **body);

static void getFriends(char **friends, const char *user);
static void appendFriend(char **friends, const char *user);

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

			if (query)
			{
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
			}
			else
			{
				printf("******* no query with this HTTP request ******** \n");
				printf("******* end of handling this request ******** \n\n\n");
			}

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
	printf("serve_request: path is parsed out: %s\n", path);
	if (starts_with("friends", path))
	{
		const char *user = dictionary_get(query, "user");
		printf("user parsed from the query: %s\n", user);
		if (!user)
		{
			clienterror(fd, "user query not found for friends", "404", "BAD", "BAD");
			return;
		}

		size_t len;
		char *resHeader, *body;
		handleGetFriends(user, &body);

		len = strlen(body);

		/* Send response headers to client */
		resHeader = ok_header(len, "text/html; charset=utf-8");

		printf("\n*******    compose response back to the client *******\n");
		printf("response header: %s", resHeader);
		printf("response body: %s\n", body);
		printf("\n*******    end of response back to the client *******\n");

		// response
		Rio_writen(fd, resHeader, strlen(resHeader));
		Rio_writen(fd, body, len);

		// clean up
		free(resHeader);
		free(body);
	}
	else if (starts_with("befriend", path))
	{
		// /befriend?user=‹user›&friends=‹friends›
		const char *user = dictionary_get(query, "user");			  //
		const char *new_friends = dictionary_get(query, "friends");   //
		if (!new_friends || !user)
		{
			clienterror(fd, "friends query not found or user not found", "404", "BAD", "BAD");
			return;
		}
		handleBeFriend(user, new_friends, NULL);
	}
	else if (starts_with("unfriend", path))
	{
		// /unfriend?user=‹user›&friends=‹friends›
		char *user = dictionary_get(query, "user");					//
		char *friends_to_remove = dictionary_get(query, "friends"); //
		if (!friends_to_remove || !user)
		{
			clienterror(fd, "friends query not found or user not found", "404", "BAD", "BAD");
			return;
		}

		printf("user: %s\n", user);
		printf("query_friends: %s\n", friends_to_remove);
		char **friends_to_remove_list = split_string(friends_to_remove, '\n'); // list of friends in the query
	}
	else if (starts_with("introduce", path))
	{
	}
	else
	{
		printf("path is not valid %s \n", path);
	}
}

static void handleGetFriends(const char *user, char **body)
{
	char *current_friends = dictionary_get(friendGraph, user);
	if (!current_friends)
	{ // if doesn't exist in the dictionary
		// insert to the dictionary
		current_friends = ""; // set to empty string
		dictionary_set(friendGraph, user, "");
	}
	unsigned char isEmpty = !strcmp(current_friends, "");

	printf("responding to the client with a 200 OKAY\n");

	if (isEmpty)
	{
		*body = strdup("");
	}
	else
	{
		char **friends_list = split_string(current_friends, '&'); // friends list

		for (int i = 0; friends_list[i] != NULL; i++)
		{
			*body = append_strings(*body, friends_list[i], "\n", NULL); // append friend_name\n to body
		}
	}
}

static void handleBeFriend(const char *user, const char *new_friends, char **body)
{
	printf("user: %s\n", user);
	printf("query_friends: %s\n", new_friends);
	char **new_friends_list = split_string(new_friends, '\n'); // list of friends in the query

	char *current_friends;
	getFriends(&current_friends, user);

	char **current_friends_list = split_string(current_friends, '&');

	// iterate through all query_friends_list, check for duplicate in friends, if not duplicate, then add
	for (int i = 0; new_friends_list[i] != NULL; i++)
	{
		char *friend = new_friends_list[i];
		unsigned char isDupl = 0;
		// check query_friends_list previous index from 0 to i contains the same value
		for (int j = 0; j < i; j++)
		{
			if (new_friends_list[j] == friend)
			{
				printf("all_friends_list: index i %u and index j %u are the suplicates\n", i, j);
				isDupl = 1;
				break;
			}
		}

		// check if friends_list contains duplicates
		for (int j = 0; current_friends_list[j] != NULL; j++)
		{
			if (current_friends_list[j] == friend)
			{
				printf("current_friends_list: index i %u and index j %u are the suplicates\n", i, j);
				isDupl = 1;
				break;
			}
		}

		if (!isDupl)
		{ // if not duplicated
			printf("is not duplicated \n");
			{
				appendFriend(&current_friends, friend); // add friend to user's friend

				printf("current friends after adding: %s\n", current_friends);
				dictionary_set(friendGraph, user, current_friends);
			}
			{
				// update the user's friend's friend to be user
				// NOTE: no need to check if friend's friends contains user
				char *friends_friends; // list of existing friends of user

				getFriends(&friends_friends, friend); // get friends
				appendFriend(&friends_friends, user); // add user to friend's friends
				dictionary_set(friendGraph, friend, friends_friends); // update user entry of the dictionary with a copy of friends_friends
			}
		}
	}
}

void getFriends(char **friends, const char *user)
{
	*friends = dictionary_get(friendGraph, user);
	if (!*friends)
	{ // if doesn't exist in the dictionary
		// insert to the dictionary
		*friends = malloc(1); // set to empty string
		dictionary_set(friendGraph, user, *friends);
	}
}

void appendFriend(char **friends, const char *new_friend)
{
	if (strcmp(*friends, "") != 0)
	{
		*friends = append_strings(*friends, "&", new_friend, NULL); // append user to friend's friends
	}
	else
	{
		*friends = append_strings(*friends, new_friend, NULL); // append user to friend's friends
	}
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
