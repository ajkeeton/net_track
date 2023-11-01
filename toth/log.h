#ifdef DEBUG_TOTH
#define DEBUG(format, args...) printf(format, ## args);
#else
#define DEBUG(format, args...) 
#endif