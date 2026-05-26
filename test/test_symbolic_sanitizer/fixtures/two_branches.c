/* Two tainted branches for testing. Reads 8 bytes from stdin, the first 4
 * are interpreted as a uint32 'data'. Two if-guards involve 'data'; both
 * must be passed for __sink_reached() to be called. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void __sink_reached(void) {}

int vuln_entry(void) {
    unsigned char buf[8];
    if (fread(buf, 1, 8, stdin) != 8) return 0;
    uint32_t data;
    memcpy(&data, buf, 4);

    if (data >= 100) return 1;           /* sanitizer-1 */
    if ((data & 1) == 0) return 2;       /* sanitizer-2 */

    __sink_reached();
    return 0;
}

int main(void) { return vuln_entry(); }
