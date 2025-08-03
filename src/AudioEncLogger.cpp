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

#include "AudioEncLogger.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <syslog.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <stdexcept>
#include <memory>
#include <mutex>

namespace AudioEncLog {

const char* to_string(LogLevel level) {
    switch (level) {
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info:  return "INFO";
        case LogLevel::Warn:  return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Alert: return "ALERT";
        case LogLevel::Emerg: return "EMERG";
        default: return "UNKNOWN";
    }
}

LogLevel parse_log_level(const std::string& level_str) {
    std::string lower_str = level_str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

    if (lower_str == "debug") { return LogLevel::Debug; }
    if (lower_str == "info") { return LogLevel::Info; }
    if (lower_str == "warn" || lower_str == "warning") { return LogLevel::Warn; }
    if (lower_str == "error") { return LogLevel::Error; }
    if (lower_str == "alert") { return LogLevel::Alert; }
    if (lower_str == "emerg" || lower_str == "emergency") { return LogLevel::Emerg; }

    throw std::invalid_argument("Invalid log level: " + level_str);
}

// StderrOutput implementation
void StderrOutput::write(LogLevel level, const std::string& message) {
    std::cerr << message << '\n';
}

// SyslogOutput implementation
SyslogOutput::SyslogOutput() : m_opened(true) {
    openlog("odr-audioenc", LOG_PID, LOG_USER);
}

SyslogOutput::~SyslogOutput() {
    if (m_opened) {
        closelog();
    }
}

void SyslogOutput::write(LogLevel level, const std::string& message) {
    int syslog_level;
    switch (level) {
        case LogLevel::Debug: syslog_level = LOG_DEBUG; break;
        case LogLevel::Info:  syslog_level = LOG_INFO; break;
        case LogLevel::Warn:  syslog_level = LOG_WARNING; break;
        case LogLevel::Error: syslog_level = LOG_ERR; break;
        case LogLevel::Alert: syslog_level = LOG_ALERT; break;
        case LogLevel::Emerg: syslog_level = LOG_EMERG; break;
        default: syslog_level = LOG_INFO; break;
    }
    syslog(syslog_level, "%s", message.c_str());
}

// LogStream implementation
LogStream::LogStream(LogLevel level) 
    : m_level(level), m_active(Logger::instance().is_level_enabled(level)) {
}

LogStream::LogStream(LogStream&& other) noexcept
    : m_level(other.m_level), m_stream(std::move(other.m_stream)), m_active(other.m_active) {
    other.m_active = false;
}

LogStream& LogStream::operator=(LogStream&& other) noexcept {
    if (this != &other) {
        m_level = other.m_level;
        m_stream = std::move(other.m_stream);
        m_active = other.m_active;
        other.m_active = false;
    }
    return *this;
}

LogStream::~LogStream() {
    if (m_active) {
        Logger::instance().log(m_level, m_stream.str());
    }
}

// Logger implementation
Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::set_level(LogLevel level) {
    m_min_level.store(level);
}

LogLevel Logger::get_level() const {
    return m_min_level.load();
}

void Logger::use_stderr() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_output = std::make_unique<StderrOutput>();
}

void Logger::use_syslog() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_output = std::make_unique<SyslogOutput>();
}

void Logger::log(LogLevel level, const std::string& message) {
    if (!is_level_enabled(level)) {
        return;
    }

    ensure_output();
    
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_output) {
        m_output->write(level, format_message(level, message));
    }
}

LogStream Logger::debug() {
    return LogStream(LogLevel::Debug);
}

LogStream Logger::info() {
    return LogStream(LogLevel::Info);
}

LogStream Logger::warn() {
    return LogStream(LogLevel::Warn);
}

LogStream Logger::error() {
    return LogStream(LogLevel::Error);
}

LogStream Logger::alert() {
    return LogStream(LogLevel::Alert);
}

LogStream Logger::emerg() {
    return LogStream(LogLevel::Emerg);
}

bool Logger::is_level_enabled(LogLevel level) const {
    return level >= m_min_level.load();
}

void Logger::ensure_output() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_output) {
        m_output = std::make_unique<StderrOutput>();
    }
}

std::string Logger::format_message(LogLevel level, const std::string& message) {
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << ms.count();
    oss << " [" << to_string(level) << "] " << message;
    
    return oss.str();
}

} // namespace AudioEncLog