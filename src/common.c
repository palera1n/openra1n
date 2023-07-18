#ifdef WIN32
#   include <windows.h>
#else
#   include <time.h>
#endif

#include <openra1n.h>

OPENRA1N_EXPORT void openra1n_sleep_ms(unsigned int ms)
{
#ifdef WIN32
    Sleep(ms);
#else
    struct timespec ts;
    
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}
