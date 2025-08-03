/*
 * Copyright (C) 2025 Matthias P. Braendli
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

#pragma once

#include <string>
#include <sstream>
#include <memory>
#include <mutex>
#include <atomic>

namespace AudioEncLog {

/**
 * @brief Log levels for the AudioEnc logger
 */
enum class LogLevel {
    Debug = 0,
    Info,
    Warn,
    Error,
    Alert,
    Emerg
};

/**
 * @brief Convert LogLevel to string
 */
const char* to_string(LogLevel level);

/**
 * @brief Parse log level from string
 * @param level_str String representation of log level (case insensitive)
 * @return LogLevel enum value
 * @throws std::invalid_argument if level_str is not valid
 */
LogLevel parse_log_level(const std::string& level_str);

/**
 * @brief Abstract base class for log output destinations
 */
class LogOutput {
public:
    virtual ~LogOutput() = default;
    virtual void write(LogLevel level, const std::string& message) = 0;
};

/**
 * @brief Log output to stderr
 */
class StderrOutput : public LogOutput {
public:
    void write(LogLevel level, const std::string& message) override;
};

/**
 * @brief Log output to syslog
 */
class SyslogOutput : public LogOutput {
public:
    SyslogOutput();
    ~SyslogOutput() override;
    void write(LogLevel level, const std::string& message) override;

private:
    bool m_opened = false;
};

/**
 * @brief Helper class for building log messages with streaming syntax
 */
class LogStream {
public:
    explicit LogStream(LogLevel level);
    LogStream(const LogStream&) = delete;
    LogStream& operator=(const LogStream&) = delete;
    LogStream(LogStream&& other) noexcept;
    LogStream& operator=(LogStream&& other) noexcept;
    ~LogStream();

    template<typename T>
    LogStream& operator<<(const T& value) {
        if (m_active) {
            m_stream << value;
        }
        return *this;
    }

private:
    LogLevel m_level;
    std::ostringstream m_stream;
    bool m_active;
};

/**
 * @brief Main logger class using singleton pattern
 */
class Logger {
public:
    /**
     * @brief Get the singleton instance
     */
    static Logger& instance();

    /**
     * @brief Set the minimum log level
     */
    void set_level(LogLevel level);

    /**
     * @brief Get the current minimum log level
     */
    LogLevel get_level() const;

    /**
     * @brief Set output to stderr (default)
     */
    void use_stderr();

    /**
     * @brief Set output to syslog
     */
    void use_syslog();

    /**
     * @brief Log a message at the specified level
     */
    void log(LogLevel level, const std::string& message);

    /**
     * @brief Create a log stream for the specified level
     */
    LogStream debug();
    LogStream info();
    LogStream warn();
    LogStream error();
    LogStream alert();
    LogStream emerg();

    /**
     * @brief Check if a log level is enabled
     */
    bool is_level_enabled(LogLevel level) const;

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    mutable std::mutex m_mutex;
    std::atomic<LogLevel> m_min_level{LogLevel::Warn};
    std::unique_ptr<LogOutput> m_output;

    void ensure_output();
    std::string format_message(LogLevel level, const std::string& message);
};

} // namespace AudioEncLog