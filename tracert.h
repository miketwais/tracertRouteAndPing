#include <iostream>
#include <sstream>
#define TRACE_MSG(msg)										\
	{														\
	std::ostringstream dbg_msg(std::ostringstream::out);	\
	dbg_msg << msg << std::endl;							\
	OutputDebugString(dbg_msg.str().c_str());				\
	}

#ifdef _WIN64
typedef icmp_echo_reply32 ICMPECHO, *PICMPECHO, FAR *LPICMPECHO;
#else
typedef icmp_echo_reply ICMPECHO, *PICMPECHO, FAR *LPICMPECHO;
#endif
