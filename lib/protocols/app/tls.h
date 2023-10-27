/**
 * @brief - Implements TLS serialize and deserialize.
 * 
 * @copyright - 2023-present. Devendra Naga. All rights reserved.
*/
#ifndef __FW_LIB_APPS_TLS_H__
#define __FW_LIB_APPS_TLS_H__

#include <packet.h>
#include <event_def.h>
#include <logger.h>

namespace firewall {

enum class Tls_Version {
    Tls_Version_1_0,
    Tls_Version_1_1,
    Tls_Version_1_2,
};

enum class Content_Type {
    Handshake = 22,
};

struct tls_hdr {
    Content_Type type;
    Tls_Version version;

    int serialize(packet &p);
    event_description deserialize(packet &p, logger *log, bool debug = false);
    void print(logger *log);
};

}

#endif


