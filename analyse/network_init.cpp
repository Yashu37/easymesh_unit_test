/*
 * HANDLER: dm_network_t::init
 *
 * Copied verbatim from unified-wifi-mesh (develop @ 1ba9529): dm_network_t::init (src/dm/dm_network.cpp) with util::get_date_time_rfc3399
 * (src/utils/util.cpp). Local array: date_time[64]. The object lives on the heap between poisoned guards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network_init.h"

namespace nit {
box_t *g_box = NULL;

/* --- copied verbatim --- */
namespace util {
char *get_date_time_rfc3399(char *buff, unsigned int len)
{
	time_t now;
    struct tm *timeinfo;

    time(&now);
    timeinfo = localtime(&now);

	memset(buff, 0, len);
	strftime(buff, len, "%Y-%m-%dT%H:%M:%SZ", timeinfo);

	return buff;
}
}

int dm_network_t::init()
{
	char date_time[EM_DATE_TIME_BUFF_SZ];

	util::get_date_time_rfc3399(date_time, EM_DATE_TIME_BUFF_SZ);

	memset(&m_net_info, 0, sizeof(em_network_info_t)); 
	strncpy(m_net_info.timestamp, date_time, EM_DATE_TIME_BUFF_SZ);
	// set the default media to Ethernet
	m_net_info.media = em_media_type_ieee8023ab;
	return 0;
}

int invoke(void) { return g_box->obj.init(); }
} /* namespace nit */
