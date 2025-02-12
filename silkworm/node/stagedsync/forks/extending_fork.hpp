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

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/context_pool.hpp>

#include "fork.hpp"
#include "silkworm/node/db/memory_mutation.hpp"

namespace silkworm::stagedsync {

namespace asio = boost::asio;

// ExtendingFork is a composition of a Fork, an in-memory database and an io_context.
// It executes the fork operations on the private io_context, so we can:
// - parallelize operations on different forks to improve performances
// - put operations on the same fork in sequence to avoid races
// The in-memory database is used to store the forked blocks & states.

class ExtendingFork {
  public:
    explicit ExtendingFork(BlockId forking_point, MainChain&, asio::io_context&);
    ExtendingFork(const ExtendingFork&) = delete;
    ExtendingFork(ExtendingFork&& orig) noexcept;
    ~ExtendingFork();

    // opening & closing
    void start_with(BlockId new_head, std::list<std::shared_ptr<Block>>&&);
    void close();

    // extension
    void extend_with(Hash head_hash, const Block& head);

    // verification
    auto verify_chain()
        -> concurrency::AwaitableFuture<VerificationResult>;
    auto notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash = std::nullopt)
        -> concurrency::AwaitableFuture<bool>;

    // state
    auto current_head() const -> BlockId;

  protected:
    void save_exception(std::exception_ptr);
    void propagate_exception_if_any();

    Fork fork_;
    asio::io_context& io_context_;    // for io
    concurrency::Context executor_;   // for pipeline execution
    std::thread thread_;              // for executor
    std::exception_ptr exception_{};  // last exception

    // cached values provided to avoid thread synchronization
    BlockId current_head_{};
};

// find the fork with the specified head
auto find_fork_by_head(std::vector<ExtendingFork>& forks, const Hash& requested_head_hash)
    -> std::vector<ExtendingFork>::iterator;

// find the fork with the head to extend
auto find_fork_to_extend(std::vector<ExtendingFork>& forks, const BlockHeader& header)
    -> std::vector<ExtendingFork>::iterator;

}  // namespace silkworm::stagedsync
