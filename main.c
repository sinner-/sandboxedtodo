#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <my_global.h>
#include <mysql.h>

#define MAX_POST_LEN 1024

int main() {

    // ensure none of our children will ever be granted more priv
    // (via setuid, capabilities, ...)
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    // ensure no escape is possible via ptrace
    prctl(PR_SET_DUMPABLE, 0);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    //For MySQL
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);

    //For sscanf
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);

    /* Do all the insecure stuff
     * insecure printf because first call to print to an output stream 
     * causes glibc to invoke fstat, which is not permitted 
     * when in SECCOMP mode.
     * mysql connection setup
     */
    printf("Content-type: text/html\r\n\r\n");

    MYSQL *con = mysql_init(NULL);
    
    if (con == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        exit(1);
    }

    if (mysql_real_connect(con, "localhost", "root", NULL, NULL, 0, NULL, 0) == NULL) {
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
        exit(1);
    }
    /* end all the insecure stuff */

    //Start sandbox
    seccomp_load(ctx);
    seccomp_release(ctx);

    if (mysql_query(con, "CREATE DATABASE IF NOT EXISTS todo")) {
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
        exit(1);
    }

    printf("<html>\n");
    printf("\t<head>\n");
    printf("\t\t<title>Sandboxed TODO</title>\n");
    printf("\t</head>\n");
    printf("\t<body>\n");
    printf("\t\t<p>Hello World</p>\n");
    printf("\t\t\t<form method='POST' action='/index'>\n");
    printf("\t\t\t\tvalue1: <input type='text' name='val1'/><br/>\n");
    printf("\t\t\t\tvalue2: <input type='text' name='val2'/><br/>\n");
    printf("\t\t\t\t<input type='submit'/></br>\n");
    printf("\t\t\t</form>\n");

    //GET
    char *query_string;
    char *param_token, *key, *value;
    query_string = getenv("QUERY_STRING");
    
    if (query_string != NULL) {
        printf("\t\t<p>Query string tokenized:</p>\n");
        while((param_token = strsep(&query_string, "&")) != NULL) {
            printf("\t\t\t<p>");
            key = strsep(&param_token, "=");
            value = strsep(&param_token, "=");
            if(value != NULL) {
                printf("%s=%s", key, value);
            }
            printf("</p>\n");
        }
    }

    //POST
    char *content_length;
    long len;
    char post_data[MAX_POST_LEN];
    char *p = post_data;
    content_length = getenv("CONTENT_LENGTH");

    if (content_length == NULL || sscanf(content_length,"%ld",&len)!=1 || len > MAX_POST_LEN) {
        printf("\t\t<p>POST error</p>\n"); 
    } else {
        fgets(post_data, len+1, stdin);
        printf("\t\t<p>POST data tokenized:</p>\n");
        while((param_token = strsep(&p, "&")) != NULL) {
            printf("\t\t\t<p>");
            key = strsep(&param_token, "=");
            value = strsep(&param_token, "=");
            if(value != NULL) {
                printf("%s=%s", key, value);
            }
            printf("</p>\n");
       }
    }

    printf("\t</body>\n");
    printf("<html>\n");

    mysql_close(con);
    exit(0);
}
