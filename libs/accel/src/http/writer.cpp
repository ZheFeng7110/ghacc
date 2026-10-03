module ghacc.accel.http.writer;

import std;
import ghacc.accel.http.message;

namespace ghacc::accel::http {

namespace {

void append_headers(std::string& out, const Headers& headers) {
    for (const auto& [name, value] : headers.fields()) {
        out += name;
        out += ": ";
        out += value;
        out += "\r\n";
    }
}

} // namespace

std::string serialize_request(const Request& request) {
    std::string out;
    out.reserve(128 + request.headers.size() * 32);
    out += request.method;
    out += ' ';
    out += request.target;
    out += ' ';
    out += request.version;
    out += "\r\n";
    append_headers(out, request.headers);
    out += "\r\n";
    return out;
}

std::string serialize_response(const Response& response) {
    std::string out;
    out.reserve(128 + response.headers.size() * 32);
    out += response.version;
    out += ' ';
    out += std::to_string(response.status);
    out += ' ';
    out += response.reason.empty() ? std::string(status_reason(response.status)) : response.reason;
    out += "\r\n";
    append_headers(out, response.headers);
    out += "\r\n";
    return out;
}

std::string_view status_reason(int status) noexcept {
    switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 411: return "Length Required";
        case 413: return "Payload Too Large";
        case 421: return "Misdirected Request";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "";
    }
}

} // namespace ghacc::accel::http
