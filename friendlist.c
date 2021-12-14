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
static void handleBeFriends(const char *user, const char *new_friends, char **body);
static void handleRemoveFriends(const char *user, const char *friends_to_remove, char **body);
static void handleIntroduce(const char *user, const char *friend, char *host, char*port, char **body);

static void addFriendsToUser(char **new_friends_list, const char *user);
static void respondOkayRequest(const int fd, char *body);
static void addFriendsToBody(const char *user, char **body);
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
			// printf("Accepted connection from (%s, %s)\n", hostname, port);
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
			{   // for POST method, some queries will be in the body
				read_postquery(&rio, headers, query);
			}

			printf("******* START of handling this request ******** \n");
			printf("Request URI: %s\n", uri);
			if (query)
			{
				serve_request(fd, query, headers, uri);
				printf("current friends graph size after serving this request: %zu\n", dictionary_count(friendGraph));
			}
			else
			{
				printf("******* terminate because no query with this HTTP request ******** \n");
			}
			printf("******* END of handling this request ******** \n\n\n");

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
	// printf("%s", buf);
	while (strcmp(buf, "\r\n"))
	{
		Rio_readlineb(rp, buf, MAXLINE);
		// printf("%s", buf);
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
		if (!user)
		{
			clienterror(fd, "user query not found for friends", "404", "BAD", "BAD");
			return;
		}

		char *body = calloc(1, 1);
		handleGetFriends(user, &body);
		respondOkayRequest(fd, body);
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
		// sending message to client
		char *body = calloc(1, 1);
		handleBeFriends(user, new_friends, &body);
		respondOkayRequest(fd, body);
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
		// sending message to client
		char *body = calloc(1, 1);
		handleRemoveFriends(user, friends_to_remove, &body);
		respondOkayRequest(fd, body);
	}
	else if (starts_with("introduce", path)) 
	{
		// sends HTTP friends request for <friend> to the server with <host> and <port>
		// /introduce?user=‹user›&friend=‹friend›&host=‹host›&port=‹port›
		char *user = dictionary_get(query, "user");
		char *friend = dictionary_get(query, "friend");
		char *host = dictionary_get(query, "host");
		char *port = dictionary_get(query, "port");
		if (!friend || !user || !host || !port)
		{
			clienterror(fd, "the query is invalid, check it again", "404", "BAD", "BAD");
			return;
		}
		char *body = malloc(1);
		handleIntroduce(user, friend, host, port, &body);
	}
	else
	{
		printf("path is not valid %s \n", path);
	}
}

static void handleIntroduce(const char *user, const char *friend, char *host, char *port, char **body) {
	int s = Open_clientfd(host, port);
	const char *CRLF = "%0D%0A";

	// heading line
	char *httpMessage = append_strings("GET ", "/friends?", "user=", friend, " HTTP/1.0", "\r\n", NULL);
	// header 
	char *header = append_strings(
							"Server: Friendlist Web Server\r\n",
							"Connection: close\r\n",
							"Content-length: ", to_string(0), "\r\n",
							"Content-type: ", "text/html; charset=utf-8", "\r\n\r\n",
							NULL);
	
	printf("******* sending HTTP request to get friends of %s *******\n", friend);
	printf("handleIntroduce::request_httpMessage: %s\n", httpMessage);
	printf("handleIntroduce::request_header: %s\n", header);
	httpMessage = append_strings(httpMessage, header, NULL);
	Rio_writen(s, httpMessage, strlen(httpMessage));

	char *response = malloc(1);
	char buf[MAXLINE];
	rio_t rio; // 
	Rio_readinitb(&rio, s);
	if (Rio_readlineb(&rio, buf, MAXLINE) <= 0) {
		printf("handleIntroduce::No actual response\n");
	}
	else {
		if (starts_with(buf, "HTTP/1.0 200 OK") == 0) {
			dictionary_t *resHeaders = read_requesthdrs(&rio);
			print_stringdictionary(resHeaders);
			
			while (strcmp(buf, "\r\n") != 0) {
				Rio_readlineb(&rio, buf, MAXLINE);
				// printf("buffer: %s\n", buf);
				response = append_strings(response, buf, NULL);
			}
		}
		else {
			printf("handleIntroduce::response header is not 200 okay: %s\n", buf);
		}
	}
	
	Close(s);
	printf("handleIntroduce::response body from server: %s\n", response);
	printf("introduce %s's friends to %s\n", friend, user);

	char **friends_list = split_string(response, '\n');
	char **friend_list = split_string(friend, '-');
	for (int i = 0; friends_list[i] != NULL; i++) {
		if (strcmp(friends_list[i], "\r") == 0) {
			free(friends_list[i]);
			friends_list[i] = NULL;
		}
	}
	
	addFriendsToUser(friend_list, user); 
	addFriendsToUser(friends_list, user);
}

static void handleGetFriends(const char *user, char **body)
{
	char *current_friends;
	getFriends(&current_friends, user);
	addFriendsToBody(user, body);
}

static void handleRemoveFriends(const char *user, const char *friends_to_remove, char **body) {
	printf("user: %s\n", user);
	printf("query_friends: %s\n", friends_to_remove);
	char **friends_to_remove_list = split_string(friends_to_remove, '\n'); // list of friends in the query

	char *current_friends;
	getFriends(&current_friends, user);

	char **current_friends_list = split_string(current_friends, '&');

	// iterate through all query_friends_list, check for duplicate in friends, if not duplicate, then add
	for (int i = 0; friends_to_remove_list[i] != NULL; i++)
	{
		char *friend = friends_to_remove_list[i];
		unsigned char friend_found = 0;

		// check if friends_list contains that friend
		for (int j = 0; current_friends_list[j] != NULL; j++)
		{
			if (strcmp(current_friends_list[j], friend) == 0)
			{
				current_friends_list[j] = ""; // change it to empty string 
				friend_found = 1;
				break;
			}
		}

		if (friend_found)
		{   
			// WARNING: POTENTIAL BUG HERE
			char *updated_friend = malloc(1);
			// construct a new string of friends
			for (int i = 0; current_friends_list[i] != NULL; i++) { 
				updated_friend = append_strings(updated_friend, current_friends_list[i], NULL);
			} 
			// set updated_friend to user
			dictionary_set(friendGraph, user, updated_friend);

			char *friends_friends; // list of existing friends of user
			getFriends(&friends_friends, friend); // get friends
			char **friends_friends_list = split_string(friends_friends, '&');
			
			// find user in friend's list of friends
			for (int i = 0; friends_friends_list[i] != NULL; i++) { 
				if (strcmp(friends_friends_list[i], user) == 0) {  // found user in friend's list of friends
					friends_friends_list[i] = ""; // change it to empty string
					char *updated_friends_friends = malloc(1);  // updated friends of friends
					// construct a new string of friends
					for (int i = 0; friends_friends_list[i] != NULL; i++) { 
						updated_friends_friends = append_strings(updated_friends_friends, friends_friends_list[i], "&", NULL);
					} 
					dictionary_set(friendGraph, friend, updated_friends_friends); // updated friends friends should not contain the user
					break;
				}
			}
		}
		else {
			printf("no such friend named: %s\n", friend);
		}
	}

	// add updated friends to body
	addFriendsToBody(user, body);
}

static void handleBeFriends(const char *user, const char *new_friends, char **body)
{
	printf("user: %s\n", user);
	// char *decoded_new_friends = query_decode(new_friends);
	printf("query_friends: %s\n\n", new_friends);

	char **new_friends_list = split_string(new_friends, '\n'); // list of friends in the query
	for (int i = 0; new_friends_list[i] != NULL; i++) {
		printf("query list index %u name: %s\n", i, new_friends_list[i]);
	}

	addFriendsToUser(new_friends_list, user);
	addFriendsToBody(user, body);
}


static void respondOkayRequest(const int fd, char *body) {
	size_t len;
	char *resHeader;
	len = strlen(body);
	resHeader = ok_header(len, "text/html; charset=utf-8");

	printf("*******    COMPOSE response back to the client *******\n");
	printf("response header: %s", resHeader);
	printf("response body: %s\n", body);
	printf("*******    END of response back to the client *******\n");

	// response
	Rio_writen(fd, resHeader, strlen(resHeader));
	Rio_writen(fd, body, len);

	// clean up
	free(resHeader);
	free(body);
}

static void addFriendsToBody(const char *user, char **body) {
	// add updated friends to body
	char *updatedFriends = NULL;
	getFriends(&updatedFriends, user);
	char ** splitUpdatedFriends = split_string(updatedFriends, '&');
	for (int i = 0; splitUpdatedFriends[i] != NULL; i++) {
		if (splitUpdatedFriends[i+1] == NULL) {
			*body = append_strings(*body, splitUpdatedFriends[i], "\n", NULL);
		}
		else {
			*body = append_strings(*body, splitUpdatedFriends[i], "\n", NULL);
		}
	}
	*body = append_strings(*body, "\r\n", NULL);
}

static void addFriendsToUser(char **new_friends_list, const char *user) {
	
	char *currentFriends = NULL;
	getFriends(&currentFriends, user);
	char ** currentFriendsList = split_string(currentFriends, '&');
	for (int i = 0; new_friends_list[i] != NULL; i++) {
		char *friend = new_friends_list[i];
		if (strcmp(friend, user) == 0) { // cannot be friend with yourself
			continue;
		}

		unsigned char isDupl = 0;
		// check query_friends_list previous index from 0 to i contains the same value
		for (int j = 0; j < i; j++)
		{
			if (strcmp(friend, new_friends_list[j]) == 0)
			{
				printf("new_friends_list: index i=%u and index j=%u are the duplicates\n", i, j);
				isDupl = 1;
				break;
			}
		}

		// check if friends_list contains duplicates
		for (int j = 0; currentFriendsList[j] != NULL; j++)
		{
			if (strcmp(friend, currentFriendsList[j]) == 0)
			{
				printf("current_friends_list: index i=%u and index j=%u are the duplicates\n", i, j);
				isDupl = 1;
				break;
			}
		}

		if (!isDupl)
		{ // if not duplicated
			{
				appendFriend(&currentFriends, friend); // add friend to user's friend
				dictionary_set(friendGraph, user, currentFriends); // insert into dictionary

				printf("adding %s to %s's friends\n", friend, user);
				printf("current friends of %s after adding: %s\n\n", user, currentFriends);
			}
			{
				// update the user's friend's friend to be user
				// NOTE: no need to check if friend's friends contains user
				char *friends_friends; // list of existing friends of user
				getFriends(&friends_friends, friend); // get friends
				appendFriend(&friends_friends, user); // add user to friend's friends
				dictionary_set(friendGraph, friend, friends_friends); // update user entry of the dictionary with a copy of friends_friends

				printf("adding %s to %s's friends\n", user, friend);
				printf("current friends of %s after adding: %s\n\n", friend, friends_friends);
			}
		}
		else {
			printf("friend %s is already friend with user %s\n", friend, user);
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
