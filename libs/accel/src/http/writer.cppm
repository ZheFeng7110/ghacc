export module ghacc.accel.http.writer;

import std;
import ghacc.accel.http.message;

export namespace ghacc::accel::http {

/// Serialize a request head (request line + headers + blank line). No body.
[[nodiscard]] std::string serialize_request(const Request& request);

/// Serialize a response head (status line + headers + blank line). No body.
[[nodiscard]] std::string serialize_response(const Response& response);

/// Canonical reason phrase for a status code, or an empty view if unknown.
[[nodiscard]] std::string_view status_reason(int status) noexcept;

} // namespace ghacc::accel::http
