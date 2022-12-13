#ifndef BASIC_H
#define BASIC_H

#define NO_ARP_ENTRY        (-2)
#define WAIT_MORE_DATA      (-3)
#define WAIT_CONNECTED      (-4)

#define CLEAR(x) memset(&(x), 0, sizeof(x))

#define SET_FLAG(V,F)       ((V)|=F)
#define CHECK_FLAG(V,F)     ((V)&F)
#define UNSET_FLAG(V,F)     ((V)&= ~F)
#define CLEAN_FLAG(V)       ((V)=0)

#endif
