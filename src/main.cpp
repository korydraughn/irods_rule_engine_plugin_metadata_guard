#include "user_administration.hpp"

#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_re_serialization.hpp>
#include <irods/irods_re_ruleexistshelper.hpp>
#include <irods/irods_get_full_path_for_config_file.hpp>
#include <irods/irods_at_scope_exit.hpp>
#include <irods/irods_query.hpp>
#include <irods/irods_logger.hpp>
#include <irods/irods_rs_comm_query.hpp>
#include <irods/irods_state_table.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <json.hpp>

#include <boost/any.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <string>
#include <algorithm>
#include <array>

namespace
{
    // clang-format off
    using log  = irods::experimental::log;
    using json = nlohmann::json;
    // clang-format on

    auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&
    {
        ruleExecInfo_t* rei{};
        irods::error result{_effect_handler("unsafe_ms_ctx", &rei)};

        if (!result.ok()) {
            THROW(result.code(), "Failed to get rule execution info");
        }

        return *rei;
    }

    template <typename Function>
    auto sudo(ruleExecInfo_t& _rei, Function _func) -> decltype(_func())
    {
        auto& auth_flag = _rei.rsComm->clientUser.authInfo.authFlag;
        const auto old_auth_flag = auth_flag;

        // Elevate privileges.
        auth_flag = LOCAL_PRIV_USER_AUTH;

        // Restore authorization flags on exit.
        irods::at_scope_exit at_scope_exit{[&auth_flag, old_auth_flag] {
            auth_flag = old_auth_flag;
        }};

        return _func();
    }

    auto load_plugin_config(ruleExecInfo_t& _rei) -> json
    {
        // Must elevate privileges so that the configuration can be retrieved.
        // Users who aren't administrators cannot retrieve metadata they don't own.
        return sudo(_rei, [&_rei] {
            std::string json_string;

            std::string gql = "select META_COLL_ATTR_VALUE "
                              "where META_COLL_ATTR_NAME = 'irods::metadata_guard' and COLL_NAME = '/";
            gql += _rei.rsComm->myEnv.rodsZone;
            gql += "'";

            for (auto&& row : irods::query{_rei.rsComm, gql}) {
                json_string = row[0];
            }

            if (json_string.empty()) {
                const char* msg = "Rule Engine Plugin Configuration not set as metadata";

                // clang-format off
                log::rule_engine::error({{"rule_engine_plugin", "metdata_guard"},
                                         {"rule_engine_plugin_function", __func__},
                                         {"log_message", msg}});
                // clang-format on

                THROW(SYS_CONFIG_FILE_ERR, msg);
            }

            return json::parse(json_string);
        });
    }

    auto user_is_administrator(const rsComm_t& conn) -> irods::error
    {
        if (irods::is_privileged_client(conn)) {
            return CODE(RULE_ENGINE_CONTINUE);
        }

        // clang-format off
        log::rule_engine::error({{"log_message", "User is not allowed to modify metadata."},
                                 {"rule_engine_plugin", "metadata_guard"}});
        // clang-format on

        return ERROR(CAT_INSUFFICIENT_PRIVILEGE_LEVEL, "User must be an admininstrator to modify metadata");
    }

    //
    // Rule Engine Plugin
    //

    template <typename ...Args>
    using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

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
        try {
            auto* input = boost::any_cast<modAVUMetadataInp_t*>(*std::next(std::begin(_rule_arguments), 2));
            auto& rei = get_rei(_effect_handler);

            const auto is_modification = [op = std::string_view{input->arg0}]() noexcept
            {
                static const auto ops = {"set", "mod", "rm", "rmw", "rmi"};
                return std::any_of(std::begin(ops), std::end(ops), [&op](auto&& mod_op) {
                    return op == mod_op;
                });
            };

            if (!is_modification()) {
                return CODE(RULE_ENGINE_CONTINUE);
            }

            const auto config = load_plugin_config(rei);

            // JSON Configuration structure:
            // {
            //   "prefixes": ["irods::"],
            //   "admin_only": true,
            //   "editors": [
            //     {"type": "group", "name": "rodsadmin"},
            //     {"type": "user",  "name": "kory"},
            //     {"type": "user",  "name": "jane#otherZone"}
            //   ]
            // }

            for (auto&& prefix : config.at("prefixes")) {
                // If the metadata attribute starts with the prefix, then verify that the user
                // can modify the metadata attribute.
                if (boost::starts_with(input->arg3, prefix.get<std::string>())) {
                    // The "admin_only" flag supersedes the "editors" configuration option.
                    if (config.count("admin_only") && config.at("admin_only").get<bool>()) {
                        return user_is_administrator(*rei.rsComm);
                    }

                    namespace ua = irods::experimental::administration;

                    const ua::user user{rei.uoic->userName, rei.uoic->rodsZone};

                    for (auto&& editor : config.at("editors")) {
                        if (const auto type = editor.at("type").get<std::string>(); type == "group") {
                            const ua::group group{editor.at("name").get<std::string>()};

                            if (ua::server::user_is_member_of_group(*rei.rsComm, group, user)) {
                                return CODE(RULE_ENGINE_CONTINUE);
                            }
                        }
                        else if (type == "user") {
                            if (editor.at("name").get<std::string>() == ua::server::local_unique_name(*rei.rsComm, user)) {
                                return CODE(RULE_ENGINE_CONTINUE);
                            }
                        }
                    }

                    break;
                }
            }

            // clang-format off
            log::rule_engine::error({{"log_message", "User is not allowed to modify metadata [attribute => " + std::string{input->arg3} + ']'},
                                     {"rule_engine_plugin", "metadata_guard"}});
            // clang-format on

            return ERROR(CAT_INSUFFICIENT_PRIVILEGE_LEVEL, "User is not allowed to modify metadata");
        }
        catch (const json::parse_error& e) {
            // clang-format off
            log::rule_engine::error({{"log_message", "Cannot parse Rule Engine Plugin configuration."},
                                     {"rule_engine_plugin", "metadata_guard"}});
            // clang-format on
        }
        catch (const json::type_error& e) {
            // clang-format off
            log::rule_engine::error({{"log_message", "Missing or incorrect configuration properties."},
                                     {"rule_engine_plugin", "metadata_guard"}});
            // clang-format on
        }
        catch (const std::exception& e) {
            // clang-format off
            log::rule_engine::error({{"log_message", e.what()},
                                     {"rule_engine_plugin", "metadata_guard"}});
            // clang-format on
        }

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

    re->add_operation("start", operation<const std::string&>{no_op});
    re->add_operation("stop", operation<const std::string&>{no_op});
    re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
    re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
    re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});
    re->add_operation("exec_rule_text", operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{not_supported});
    re->add_operation("exec_rule_expression", operation<const std::string&, msParamArray_t*, irods::callback>{not_supported});

    return re;
}

