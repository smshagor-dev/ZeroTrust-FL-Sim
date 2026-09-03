#include <pybind11/pybind11.h>

#include <string>

namespace py = pybind11;

namespace zerotrust {

std::string backend_info()
{
    return "ZeroTrust-FL-Sim native aggregation backend";
}

}  // namespace zerotrust

PYBIND11_MODULE(zerotrust_agg, module)
{
    module.doc() = "Native aggregation primitives for ZeroTrust-FL-Sim";
    module.def(
        "backend_info",
        &zerotrust::backend_info,
        "Return native aggregation backend information"
    );
}
