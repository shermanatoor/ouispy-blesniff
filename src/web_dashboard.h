#pragma once

#include <Arduino.h>

namespace web_dashboard {

bool init();
void tick();
uint32_t connected_clients();
uint32_t ws_dropped();          // adverts discarded because a WS client queue was full

} // namespace web_dashboard
