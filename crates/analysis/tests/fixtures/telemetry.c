/* Fixture for the built-in code map (crates/analysis/src/code).
 * main -> collect_id() (gethostname) -> upload() (socket/connect/send with a URL).
 * Built with:
 *   gcc -O1 -fno-inline -o telemetry-x86_64.elf telemetry.c
 *   gcc -O1 -fno-inline -fno-plt -s -o telemetry-x86_64-noplt-stripped.elf telemetry.c
 *   gcc -m32 -O1 -fno-inline -o telemetry-i386.elf telemetry.c
 * Never executed by tests. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *ENDPOINT = "https://telemetry.example.com/v1/collect";

__attribute__((noinline)) int upload(const char *payload) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(443);
    inet_pton(AF_INET, "203.0.113.7", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) return -1;
    char buf[512];
    snprintf(buf, sizeof buf, "POST %s\r\nid=%s", ENDPOINT, payload);
    send(fd, buf, strlen(buf), 0);
    return close(fd);
}

__attribute__((noinline)) int collect_id(void) {
    char host[256];
    if (gethostname(host, sizeof host) != 0) return -1;
    return upload(host);
}

__attribute__((noinline)) void write_config(void) {
    FILE *f = fopen("/tmp/.telemetry-config", "w");
    if (f) { fputs("enabled=1\n", f); fclose(f); }
}

int main(void) {
    write_config();
    return collect_id();
}
