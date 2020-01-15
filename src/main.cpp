#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/filesystem.hpp>
#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <json.hpp>
#include <boost/any.hpp>

namespace
{
    // clang-format off
    namespace fs = irods::experimental::filesystem;

    using log    = irods::experimental::log;
    using json   = nlohmann::json;
    // clang-format on

    //
    // Rule Engine Plugin
    //

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

    auto start(irods::default_re_ctx&, const std::string& _instance_name) -> irods::error
    {
        std::string config_path;

        if (auto error = irods::get_full_path_for_config_file("server_config.json", config_path);
            !error.ok())
        {
            const char* msg = "Server configuration not found";

            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "metdata_guard"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", msg}});
            // clang-format on

            return ERROR(SYS_CONFIG_FILE_ERR, msg);
        }

        // clang-format off
        log::rule_engine::trace({{"rule_engine_plugin", "metdata_guard"},
                                 {"rule_engine_plugin_function", __func__},
                                 {"log_message", "Reading plugin configuration ..."}});
        // clang-format on

        json config;

        {
            std::ifstream config_file{config_path};
            config_file >> config;
        }

        try {
            const auto get_prop = [](const json& _config, auto&& _name) -> std::string
            {
                try {
                    return _config.at(_name).template get<std::string>();
                }
                catch (...) {
                    throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find rule engine "
                                                         "plugin configuration property [{}]", _name)};
                }
            };

            for (const auto& re : config.at(irods::CFG_PLUGIN_CONFIGURATION_KW).at(irods::PLUGIN_TYPE_RULE_ENGINE)) {
                if (_instance_name == re.at(irods::CFG_INSTANCE_NAME_KW).get<std::string>()) {
                    const auto& plugin_config = re.at(irods::CFG_PLUGIN_SPECIFIC_CONFIGURATION_KW);

                    const auto& attr_names = [&plugin_config] {
                        try {
                            return plugin_config.at("metadata_attribute_names");
                        }
                        catch (...) {
                            throw std::runtime_error{fmt::format("Logical Quotas Policy: Failed to find rule engine "
                                                                 "plugin configuration property [metadata_attribute_name]")};
                        }
                    }();

                    irods::instance_configuration instance_config{{get_prop(plugin_config, "namespace"),
                                                                   get_prop(attr_names, "maximum_number_of_data_objects"),
                                                                   get_prop(attr_names, "maximum_size_in_bytes"),
                                                                   get_prop(attr_names, "total_number_of_data_objects"),
                                                                   get_prop(attr_names, "total_size_in_bytes")}};

                    instance_configs.insert_or_assign(_instance_name, instance_config);

                    return SUCCESS();
                }
            }
        }
        catch (const std::exception& e) {
            // clang-format off
            log::rule_engine::error({{"rule_engine_plugin", "metdata_guard"},
                                     {"rule_engine_plugin_function", __func__},
                                     {"log_message", "Bad rule engine plugin configuration"}});
            // clang-format on

            return ERROR(SYS_CONFIG_FILE_ERR, e.what());
        }

        return ERROR(SYS_CONFIG_FILE_ERR, "[metdata_guard] Bad rule engine plugin configuration");
    }

    auto rule_exists(irods::default_re_ctx&, const std::string& _rule_name, bool& _exists) -> irods::error
    {
        _exists = (_rule_name == "pep_api_mod_avu_metadata_pre");
        return SUCCESS();
    }

    auto list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules) -> irods::error
    {
        _rules.push_back("pep_api_mod_avu_metadata_pre");
        return SUCCESS();
    }

    auto exec_rule(irods::default_re_ctx&,
                   const std::string& _rule_name,
                   std::list<boost::any>& _rule_arguments,
                   irods::callback _effect_handler) -> irods::error
    {
        //log::rule_engine::error("Rule not supported in rule engine plugin [rule => {}]", _rule_name);

        return CODE(RULE_ENGINE_CONTINUE);
    }
} // namespace (anonymous)

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C"
auto plugin_factory(const std::string& _instance_name, const std::string& _context) -> pluggable_rule_engine*
{
    // clang-format off
    const auto no_op         = [](auto&&...) { return SUCCESS(); };
    const auto not_supported = [](auto&&...) { return CODE(SYS_NOT_SUPPORTED); };
    // clang-format on

    auto* re = new pluggable_rule_engine{_instance_name, _context};

    re->add_operation("start", operation<const std::string&>{start});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{not_supported});

    return re;
}

