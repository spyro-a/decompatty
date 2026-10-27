#include <core/analysis_engine.hpp>

#include <QMetaObject>
#include <QSettings>

#include <algorithm>
#include <chrono>
#include <exception>
#include <semaphore>
#include <utility>

void threading_settings_t::normalize() noexcept {
    workers = std::min(workers, 64u);
    queued_batches = std::clamp(queued_batches, 1u, 64u);
    if (batch_bytes != 4096 && batch_bytes != 16384 && batch_bytes != 65536)
        batch_bytes = 16384;
}

unsigned threading_settings_t::worker_count() const noexcept {
    if (!parallel)
        return 1;
    const auto available = std::max(1u, std::thread::hardware_concurrency());
    return workers == 0 ? std::clamp(available - 1, 1u, 64u) : std::clamp(workers, 1u, 64u);
}

bool analysis_engine_t::set_threading_settings(threading_settings_t settings) {
    settings.normalize();
    QSettings saved(QSettings::defaultFormat(), QSettings::UserScope, "decompatty", "decompatty");
    saved.beginGroup("threading");
    saved.setValue("parallel", settings.parallel);
    saved.setValue("workers", settings.workers);
    saved.setValue("batch_bytes", settings.batch_bytes);
    saved.setValue("queued_batches", settings.queued_batches);
    saved.sync();
    if (saved.status() != QSettings::NoError)
        return false;
    settings_ = settings;
    return true;
}

const decompatty_arch_api* resolve_arch(void* ctx, std::uint32_t cpu, std::uint32_t format) {
    return static_cast<analysis_engine_t*>(ctx)->arch_loader().find(cpu, format);
}

analysis_engine_t::analysis_engine_t(QObject* parent)
    : QObject(parent), worker_([this](std::stop_token stop) { work(stop); }) {
    QSettings saved(QSettings::defaultFormat(), QSettings::UserScope, "decompatty", "decompatty");
    saved.beginGroup("threading");
    settings_.parallel = saved.value("parallel", false).toBool();
    settings_.workers = saved.value("workers", 0).toUInt();
    settings_.batch_bytes = saved.value("batch_bytes", 16384).toUInt();
    settings_.queued_batches = saved.value("queued_batches", 8).toUInt();
    settings_.normalize();
}

analysis_engine_t::~analysis_engine_t() {
    cancellation_.request_stop();
    worker_.request_stop();
    wake_.notify_all();
    worker_.join();
}

void analysis_engine_t::cancel() {
    cancellation_.request_stop();
    ++generation_;
    loading_ = false;
    std::lock_guard lock(mutex_);
    pending_.reset();
}

bool analysis_engine_t::load(const char* path) {
    if (!path || !*path)
        return false;

    cancel();
    cancellation_ = std::stop_source{};
    binary_.reset();
    batches_.clear();
    instruction_count_ = 0;
    loading_ = true;
    {
        std::lock_guard lock(mutex_);
        pending_ = job_t{path, generation_, cancellation_.get_token(), settings_};
    }
    wake_.notify_one();
    return true;
}

void analysis_engine_t::work(std::stop_token stop) {
    while (!stop.stop_requested()) {
        job_t job;
        {
            std::unique_lock lock(mutex_);
            if (!wake_.wait(lock, stop, [this] { return pending_.has_value(); }))
                return;
            job = std::move(*pending_);
            pending_.reset();
        }

        auto logger = [this, generation = job.generation](const std::string& message) {
            QMetaObject::invokeMethod(this, [this, generation, message] {
                if (generation == generation_ && logger_)
                    logger_(message);
            }, Qt::QueuedConnection);
        };

        bool success = false;
        try {
            std::shared_ptr<binary_file_t> file = open_binary(job.path.c_str(), logger, resolve_arch, this, true);
            if (job.stop.stop_requested())
                continue;
            if (file && file->valid()) {
                QMetaObject::invokeMethod(this, [this, generation = job.generation, file] {
                    if (generation != generation_)
                        return;
                    binary_ = file;
                    emit binary_ready();
                }, Qt::QueuedConnection);

                // Bound queued batches so decoding cannot overwhelm the event loop.
                auto capacity = std::make_shared<std::counting_semaphore<64>>(job.settings.queued_batches);
                success = file->disassemble([this, &job, capacity](instruction_batch_t batch) {
                    while (!capacity->try_acquire_for(std::chrono::milliseconds(10))) {
                        if (job.stop.stop_requested())
                            return false;
                    }
                    if (job.stop.stop_requested()) {
                        capacity->release();
                        return false;
                    }
                    QMetaObject::invokeMethod(this, [this, generation = job.generation, capacity, batch = std::move(batch)] {
                        capacity->release();
                        if (generation != generation_)
                            return;
                        instruction_count_ += batch->size();
                        batches_.push_back(batch);
                        emit instructions_ready(batch);
                    }, Qt::QueuedConnection);
                    return true;
                }, job.stop, {job.settings.worker_count(), job.settings.batch_bytes});
            }
        } catch (const std::exception& error) {
            logger(std::string("analysis failed: ") + error.what());
        }

        QMetaObject::invokeMethod(this, [this, generation = job.generation, success] {
            if (generation != generation_)
                return;
            loading_ = false;
            emit load_finished(success);
        }, Qt::QueuedConnection);
    }
}

void analysis_engine_t::discover_archs(const std::string& dir) {
    arch_.discover(dir);
}
