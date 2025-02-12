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

#include "admin_api.hpp"

#include <string>

#include <silkworm/silkrpc/json/types.hpp>

namespace silkworm::rpc::commands {

// https://eth.wiki/json-rpc/API#admin_nodeinfo
awaitable<void> AdminRpcApi::handle_admin_node_info(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto node_infos = co_await backend_->engine_node_info();
        if (node_infos.size() > 0) {
            reply = make_json_content(request["id"], node_infos[0]);
        } else {
            reply = make_json_content(request["id"], nlohmann::json::object());
        }
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }
    co_return;
}

// https://eth.wiki/json-rpc/API#admin_peers
awaitable<void> AdminRpcApi::handle_admin_peers(const nlohmann::json& request, nlohmann::json& reply) {
    try {
        const auto peers = co_await backend_->peers();
        reply = make_json_content(request["id"], peers);
    } catch (const std::exception& e) {
        SILKRPC_ERROR << "exception: " << e.what() << " processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], -32000, e.what());
    } catch (...) {
        SILKRPC_ERROR << "unexpected exception processing request: " << request.dump() << "\n";
        reply = make_json_error(request["id"], 100, "unexpected exception");
    }
    co_return;
}

}  // namespace silkworm::rpc::commands
