#ifndef __FW_SRC_FILTERS_TCP_FILTER_H__
#define __FW_SRC_FILTERS_TCP_FILTER_H__

#include <memory>

namespace firewall {

struct parser;

enum class Tcp_State {
    SYN_SENT,
    SYN_RECIVED,
    SYN_ACK_SENT,
    ACK_SENT,
};

/**
 * @brief - implements TCP state machine.
*/
class tcp_state_machine {
    public:
        explicit tcp_state_machine(parser &p);

    private:
        bool is_server_;
        Tcp_State cur_state_;
};

/**
 * @brief - Implements an over arching filter for TCP.
*/
class tcp_filter {
    public:
        static tcp_filter *instance()
        {
            static tcp_filter tcp_f;
            return &tcp_f;
        }

        ~tcp_filter() { }

        /**
         * @brief - check and add to the TCP state machine.
        */
        void add_pkt(parser &p);

    private:
        std::shared_ptr<tcp_state_machine> flows_;
};

}

#endif
