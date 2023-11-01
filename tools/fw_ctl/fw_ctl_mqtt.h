#ifndef __FW_CTL_MQTT_H__
#define __FW_CTL_MQTT_H__

#include <string>
#include <fw_ctl_global_queue.h>

namespace firewall {

int mqtt_listen(const std::string &uri, const std::string &topic);

}

#endif
