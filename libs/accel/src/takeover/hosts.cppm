export module ghacc.accel.takeover.hosts;

import std;

export namespace ghacc::accel {

/// One `ip host` line managed inside the ghacc marker block.
struct HostEntry {
    std::string ip;
    std::string host;
};

/// Reads and rewrites the system hosts file using a marked block.
///
/// Only the lines between `begin_marker()` and `end_marker()` are touched; the
/// rest of the file is preserved byte for byte. The original file is backed up
/// (once) before the first modification so it can be restored by hand or with
/// `revert()`.
class HostsManager {
public:
    explicit HostsManager(std::filesystem::path path = default_path(),
                          std::filesystem::path backup = default_backup_path());

    /// Platform hosts path (`/etc/hosts`, `%SystemRoot%\System32\drivers\etc\hosts`).
    [[nodiscard]] static std::filesystem::path default_path();
    /// Platform state directory backup path.
    [[nodiscard]] static std::filesystem::path default_backup_path();
    [[nodiscard]] static std::string_view begin_marker() noexcept;
    [[nodiscard]] static std::string_view end_marker() noexcept;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }
    [[nodiscard]] const std::filesystem::path& backup_path() const noexcept { return backup_; }

    /// Whether the current user may write the hosts file (or its directory).
    [[nodiscard]] bool is_writable() const;

    /// Guidance shown when `is_writable()` is false.
    [[nodiscard]] std::string permission_hint() const;

    [[nodiscard]] bool contains_our_block() const;

    /// Entries currently inside the marker block (empty if there is none).
    [[nodiscard]] std::vector<HostEntry> current_block() const;

    /// Replace the marker block with `entries` (inserting it when absent).
    /// Backs up the original file once. Idempotent; an empty `entries` removes
    /// the block (same as `revert()`).
    [[nodiscard]] std::expected<void, std::string> apply(std::span<const HostEntry> entries);

    /// Remove the marker block, leaving the rest of the file untouched.
    [[nodiscard]] std::expected<void, std::string> revert();

private:
    std::filesystem::path path_;
    std::filesystem::path backup_;
};

} // namespace ghacc::accel
