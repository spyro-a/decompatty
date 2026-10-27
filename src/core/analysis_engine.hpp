#pragma once

#include <format/binary_file.hpp>
#include <core/arch_loader.hpp>

#include <QObject>

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>

struct threading_settings_t {
    bool parallel = false;
    unsigned workers = 0; // zero selects an automatic limit
    unsigned batch_bytes = 16384;
    unsigned queued_batches = 8;

    unsigned worker_count() const noexcept;
    void normalize() noexcept;
};

class analysis_engine_t : public QObject {
    Q_OBJECT
public:
    explicit analysis_engine_t(QObject* parent = nullptr);
    ~analysis_engine_t();
    analysis_engine_t(const analysis_engine_t&) = delete;
    analysis_engine_t& operator=(const analysis_engine_t&) = delete;

    // Call from the UI thread. Results are delivered there through queued callbacks.
    bool load(const char* path);
    void cancel();
    const threading_settings_t& threading_settings() const noexcept { return settings_; }
    bool set_threading_settings(threading_settings_t settings);

    void set_logger(log_sink_t logger) noexcept {
        logger_ = std::move(logger);
        arch_.set_logger(logger_);
    }

    void discover_archs(const std::string& dir);
    const log_sink_t& logger() const noexcept { return logger_; }
    const binary_file_t* binary() const noexcept { return binary_.get(); }
    std::shared_ptr<const binary_file_t> shared_binary() const noexcept { return binary_; }
    bool has_binary() const noexcept { return binary_ != nullptr; }
    bool loading() const noexcept { return loading_; }
    const std::vector<instruction_batch_t>& batches() const noexcept { return batches_; }
    std::size_t instruction_count() const noexcept { return instruction_count_; }

    arch_loader_t& arch_loader() noexcept { return arch_; }
    const arch_loader_t& arch_loader() const noexcept { return arch_; }

    binary_format_t format() const noexcept {
        return binary_ ? binary_->format() : binary_format_t::unknown;
    }
    cpu_type_t architecture() const noexcept {
        return binary_ ? binary_->architecture() : cpu_type_t::unknown;
    }
    bitness_t bitness() const noexcept {
        return binary_ ? binary_->bitness() : bitness_t::unknown;
    }
    endianness_t endianness() const noexcept {
        return binary_ ? binary_->endianness() : endianness_t::unknown;
    }

signals:
    void binary_ready();
    void instructions_ready(instruction_batch_t batch);
    void load_finished(bool success);

private:
    struct job_t {
        std::string path;
        std::uint64_t generation;
        std::stop_token stop;
        threading_settings_t settings;
    };

    void work(std::stop_token stop);

    threading_settings_t settings_;
    std::shared_ptr<binary_file_t> binary_;
    std::vector<instruction_batch_t> batches_;
    std::size_t instruction_count_ = 0;
    bool loading_ = false;
    std::uint64_t generation_ = 0;
    log_sink_t logger_;
    arch_loader_t arch_;

    std::mutex mutex_;
    std::condition_variable_any wake_;
    std::optional<job_t> pending_;
    std::stop_source cancellation_;
    std::jthread worker_;
};
