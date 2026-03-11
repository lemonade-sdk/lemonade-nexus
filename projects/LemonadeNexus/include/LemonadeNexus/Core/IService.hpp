#pragma once

#include <concepts>
#include <string_view>

namespace nexus::core {

/// CRTP base for all services in the coordination server.
/// Derived must implement: void on_start(), void on_stop(), std::string_view name() const
template <typename Derived>
class IService {
public:
    void start() {
        self().on_start();
    }

    void stop() {
        self().on_stop();
    }

    [[nodiscard]] std::string_view service_name() const {
        return self().name();
    }

protected:
    ~IService() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept that constrains a type to be a valid IService-derived CRTP class
template <typename T>
concept ServiceType = requires(T t) {
    { t.on_start() };
    { t.on_stop() };
    { t.name() } -> std::convertible_to<std::string_view>;
};

} // namespace nexus::core
