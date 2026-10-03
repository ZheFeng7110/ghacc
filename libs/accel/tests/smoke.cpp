import std;
import boost.ut;
import ghacc.accel;

using namespace boost::ut;

int main() {
    "version is set"_test = [] {
        expect(ghacc::accel::version == "0.1.0");
    };
    return 0;
}
