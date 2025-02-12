/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "writer.hpp"

#include <algorithm>
#include <utility>

#include <boost/asio/detached.hpp>
#include <boost/asio/write.hpp>

#include <silkworm/silkrpc/common/log.hpp>

namespace silkworm::rpc {

const std::string kChunkSep{'\r', '\n'};                     // NOLINT(runtime/string)
const std::string kFinalChunk{'0', '\r', '\n', '\r', '\n'};  // NOLINT(runtime/string)

ChunksWriter::ChunksWriter(Writer& writer, std::size_t chunck_size)
    : writer_(writer), chunk_size_(chunck_size), available_(chunck_size), buffer_{new char[chunk_size_]} {
    std::memset(buffer_.get(), 0, chunk_size_);
}

void ChunksWriter::write(const std::string& content) {
    auto c_str = content.c_str();
    auto size = content.size();

    SILKRPC_DEBUG << "ChunksWriter::write available_: " << available_
                  << " size: " << size
                  << std::endl
                  << std::flush;

    char* buffer_start = buffer_.get() + (chunk_size_ - available_);
    if (available_ > size) {
        std::strncpy(buffer_start, c_str, size);
        available_ -= size;
        return;
    }

    while (size > 0) {
        const auto count = std::min(available_, size);
        std::strncpy(buffer_start, c_str, count);
        size -= count;
        c_str += count;
        available_ -= count;
        if (available_ > 0) {
            break;
        }
        flush();

        buffer_start = buffer_.get();
    }
}

void ChunksWriter::close() {
    flush();
    writer_.write(kFinalChunk);
    writer_.close();
}

void ChunksWriter::flush() {
    auto size = chunk_size_ - available_;
    SILKRPC_DEBUG << "ChunksWriter::flush available_: " << available_
                  << " size: " << size
                  << std::endl
                  << std::flush;

    if (size > 0) {
        std::stringstream stream;
        stream << std::hex << size << "\r\n";

        writer_.write(stream.str());
        std::string str{buffer_.get(), size};
        writer_.write(str);
        writer_.write(kChunkSep);
    }
    available_ = chunk_size_;
    std::memset(buffer_.get(), 0, chunk_size_);
}

}  // namespace silkworm::rpc
