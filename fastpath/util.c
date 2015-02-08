

static const unsigned char bitmask[8] = {
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
};

void bitlist_set(unsigned char *bitlist, uint32_t bit)
{
    bitlist[bit/8] |= bitmask[bit%8];
}

void bitlist_clear(unsigned char *bitlist, uint32_t bit)
{
    bitlist[bit/8] &= ~bitmask[bit%8];
}

uint32_t bitlist_test(unsigned char *bitlist, uint32_t bit)
{
    return (bitlist[bit/8] & bitmask[bit%8]) ? 1 : 0;
}

char * strtrim( char * str )
{
    char *p;
    int len;

    if ( (str != NULL) && (len = strlen(str)) ) {
        /* skip white spaces at the front of the string */
        for (; *str != 0; str++ )
            if ( (*str != ' ') && (*str != '\t') && (*str != '\r') && (*str != '\n') )
                break;

        len = strlen(str);
        if ( len == 0 )
            return str;

        // Trim trailing characters
        for ( p = &str[len-1]; p > str; p-- ) {
            if ( (*p != ' ') && (*p != '\t') && (*p != '\r') && (*p != '\n') )
                break;
            *p = '\0';
        }
    }
    return str;
}

uint32_t strparse(char * str, const char * delim, char ** entries, uint32_t max_entries)
{
    uint32_t i;
    char *saved;

    if ( (str == NULL) || (delim == NULL) || (entries == NULL) || (max_entries == 0) )
        return 0;

    memset(entries, '\0', (sizeof(char *) * max_entries));

    for(i = 0; i < max_entries; i++) {
        entries[i] = strtok_r(str, delim, &saved);
        str = NULL;
        if ( entries[i] == NULL )        // We are done.
            break;

        entries[i] = wr_strtrim(entries[i]);
    }

    return i;
}

int parse_port_list(char *list, uint8_t *map)
{
    char *p;
    int k, i;
    char *arr[33];

    if ( list == NULL )
        return 1;

    // Split up the string by ',' for each list or range set
    k = strparse(p, ",", arr, sizeof(arr)/sizeof(arr[0]));
    if ( k == 0 )
        return 1;

    for (i = 0; (i < k) && arr[i]; i++) {
        p = strchr(arr[i], '-');
        if ( p != NULL ) {
            // Found a range list
            uint32_t l, h;
            *p++ = '\0';
            l = strtol(arr[i], NULL, 10);
            h = strtol(p, NULL, 10);
            do {
                bitlist_set(map, l);
            } while( ++l <= h );
        } else {
            // Must be a single value
            bitlist_set(map, strtol(arr[i], NULL, 10));
        }
    }
    return 0;
}


