//
// Created by fulongbin on 2019-06-28.
//

#ifndef ART_LEARNING_BASE_H
#define ART_LEARNING_BASE_H
#include <boost/log/trivial.hpp>

#define log_trace BOOST_LOG_TRIVIAL(trace)
#define log_debug BOOST_LOG_TRIVIAL(debug)
#define log_info BOOST_LOG_TRIVIAL(info)
#define log_warning BOOST_LOG_TRIVIAL(warning)
#define log_error BOOST_LOG_TRIVIAL(error)
#define log_fata BOOST_LOG_TRIVIAL(fatal)

using dex_byte = int8_t;
using dex_ubyte = u_int8_t;
using dex_short = int16_t;
using dex_ushort = u_int16_t;
using dex_int = int32_t;
using dex_uint =  int32_t;
using dex_long = int64_t ;
using dex_ulong = u_int64_t;

namespace base {
    bool ReadFileToString(std::string filename, std::string &content);
}



#endif //ART_LEARNING_BASE_H
