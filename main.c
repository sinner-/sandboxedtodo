#include <stdio.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <my_global.h>
#include <mysql.h>

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

    //Need to do an insecure printf first
    //TODO: Hunt down and explain reason
    printf("Content-type: text/html\r\n\r\n");

    /* Do MySQL connection setup outside of sandbox */
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
    /* Finish connection setup */

    //Start sandbox
    seccomp_load(ctx);

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
    printf("\t</body>\n");
    printf("<html>\n");

    mysql_close(con);
    return(0);
}
