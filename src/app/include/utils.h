
#ifndef __UTILS_H__
#define __UTILS_H__

void bitlist_set(unsigned char *bitlist, uint32_t bit);
void bitlist_clear(unsigned char *bitlist, uint32_t bit);
uint32_t bitlist_test(unsigned char *bitlist, uint32_t bit);

char *strtrim(char * str);
uint32_t strparse(char * str, const char * delim, char ** entries, uint32_t max_entries);

int parse_port_list(char *list, uint8_t *map);

#endif

