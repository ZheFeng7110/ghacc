export module ghacc.cli;

export namespace ghacc::app {

/// Parse `argv` with `mcpplibs.cmdline` and run the selected command.
int run_cli(int argc, char** argv);

} // namespace ghacc::app
