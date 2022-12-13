#include <stdlib.h>
#include <string.h>

/* netcat calls readpassphrase(3bsd) with RPP_REQUIRE_TTY so it's bound
 * to fail in our test harness.  We LD_PRELOAD this program to inject
 * passphrases via environment variables instead. */
char *
readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags) {
    return strncpy(buf, getenv("PASSPHRASE"), bufsiz);
}
