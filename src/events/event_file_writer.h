/**
 * @brief - Implements event file writer.
 * 
 * @copyright - 2023-present All rights reserved. Devendra Naga.
*/
#ifndef __FW_EVENT_FILE_WRITER_H__
#define __FW_EVENT_FILE_WRITER_H__

#include <iostream>
#include <string>
#include <common.h>
#include <event_def.h>
#include <event.h>
#include <event_msg.h>

namespace firewall {

/**
 * @brief - implements writing events to a file. It formats the events before writing.
*/
class event_file_writer {
    public:
        explicit event_file_writer() : filesize_bytes_(0),
                                       cur_size_(0),
                                       fp_(nullptr)
        { }
        ~event_file_writer()
        {
            if (fp_) {
                fflush(fp_);
                fclose(fp_);
				fp_ = nullptr;
            }
        }

        /**
         * @brief - initializes the event file writer.
         * 
         * @param [in] filepath - filepath of the event.
         * @param [in] filesize_bytes - filesize to rotate.
         *
         * @return fw_error_type::eNo_Error on success and others on failure.
        */
        fw_error_type init(const std::string filepath, uint32_t filesize_bytes);

        /**
         * @brief - writes events to the event log. Right now no encryption.
         * 
         * @param [in] evt - firewall event.
         * 
         * @return fw_error_type::eNo_Error.
        */
        fw_error_type write(const event &evt);

    private:
        //
        // @brief - create a filename and return it in the given filename parameter.
        fw_error_type create_new_file();

        std::string filepath_;
        uint32_t filesize_bytes_;
        uint32_t cur_size_;
        FILE *fp_;
};

}

#endif

