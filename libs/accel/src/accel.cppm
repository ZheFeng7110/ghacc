export module ghacc.accel;

import std;

export import ghacc.accel.rule;
export import ghacc.accel.flow;
export import ghacc.accel.net.dns;
export import ghacc.accel.net.resolver;
export import ghacc.accel.ca.authority;
export import ghacc.accel.log;
export import ghacc.accel.provider;
export import ghacc.accel.provider.github;
export import ghacc.accel.provider.steam;
export import ghacc.accel.config;

export namespace ghacc::accel {

/// Library version string.
inline constexpr std::string_view version = "0.1.0";

} // namespace ghacc::accel
