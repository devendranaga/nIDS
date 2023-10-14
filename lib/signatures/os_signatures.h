/**
 * @brief - Stores OS signatures detected so far on a frame.
 * 
 * @copyright - 2023-present. All rights reserved. Devendra Naga.
 */
#ifndef __FW_OS_SIGNATURES_H__
#define __FW_OS_SIGNATURES_H__

namespace firewall {

/**
 * @brief - Type of OS.
*/
enum class os_type {
	Linux_2_4,
	Linux_4_10_2015_or_Later,
	Win_XP,
	Win_10,
	Win_Server_2008,
	Win_Server_2019,
	Mac_OS_2001_or_Later,
	Unknown,
};

class os_signature {
	public:
		~os_signature() { }

		static os_signature *instance() {
			static os_signature sig;
			return &sig;
		}

		void set_os_type(os_type type) { type_ = type; }
		os_type get_os_type() { return type_; }

	private:
		explicit os_signature() { }
		os_type type_;
};

}

#endif


