#ifndef HELPER_H
#define HELPER_H
unsigned int ip_str_to_num(const char *buf)

{

    unsigned int tmpip[4] = {0};

    unsigned int tmpip32 = 0;

 

    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];

    return tmpip32;

}
#endif