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

#pragma once

#include <silkworm/sentry/api/api_common/service.hpp>

#include "service_router.hpp"

namespace silkworm::sentry::api::router {

class DirectService : public api_common::Service {
  public:
    explicit DirectService(ServiceRouter router)
        : router_(std::move(router)) {}
    ~DirectService() override = default;

    boost::asio::awaitable<void> set_status(eth::StatusData status_data) override;
    boost::asio::awaitable<uint8_t> handshake() override;
    boost::asio::awaitable<NodeInfos> node_infos() override;

    boost::asio::awaitable<PeerKeys> send_message_by_id(common::Message message, common::EccPublicKey public_key) override;
    boost::asio::awaitable<PeerKeys> send_message_to_random_peers(common::Message message, size_t max_peers) override;
    boost::asio::awaitable<PeerKeys> send_message_to_all(common::Message message) override;
    boost::asio::awaitable<PeerKeys> send_message_by_min_block(common::Message message, size_t max_peers) override;
    boost::asio::awaitable<void> peer_min_block(common::EccPublicKey public_key) override;
    boost::asio::awaitable<void> messages(
        api_common::MessageIdSet message_id_filter,
        std::function<boost::asio::awaitable<void>(api_common::MessageFromPeer)> consumer) override;

    boost::asio::awaitable<api_common::PeerInfos> peers() override;
    boost::asio::awaitable<size_t> peer_count() override;
    boost::asio::awaitable<std::optional<api_common::PeerInfo>> peer_by_id(common::EccPublicKey public_key) override;
    boost::asio::awaitable<void> penalize_peer(common::EccPublicKey public_key) override;
    boost::asio::awaitable<void> peer_events(std::function<boost::asio::awaitable<void>(api_common::PeerEvent)> consumer) override;

  private:
    ServiceRouter router_;
};

}  // namespace silkworm::sentry::api::router
