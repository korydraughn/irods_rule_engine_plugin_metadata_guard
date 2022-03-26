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
#include <irods/user_administration.hpp>
#include <irods/scoped_privileged_client.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <boost/any.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <string>
#include <algorithm>
#include <array>
#include <optional>

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

    auto load_plugin_config(ruleExecInfo_t& _rei) -> std::optional<json>
    {
        // Must elevate privileges so that the configuration can be retrieved.
        // Users who aren't administrators cannot retrieve metadata they don't own.
        irods::experimental::scoped_privileged_client spc{*_rei.rsComm};

        const auto gql = fmt::format("select META_COLL_ATTR_VALUE "
                                     "where META_COLL_ATTR_NAME = 'irods::metadata_guard' and COLL_NAME = '/{}'",
                                     _rei.rsComm->myEnv.rodsZone);

        if (irods::query q{_rei.rsComm, gql}; q.size() > 0) {
            try {
                return json::parse(q.front()[0]);
            }
            catch (const json::exception&) {
                const char* msg = "Cannot parse Rule Engine Plugin configuration";
                log::rule_engine::error({{"log_message", fmt::format("{}.", msg)}, {"rule_engine_plugin", "metadata_guard"}});
                THROW(SYS_CONFIG_FILE_ERR, msg);
            }
        }

        return std::nullopt;
    }

    auto user_is_administrator(rsComm_t& conn) -> irods::error
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
        _exists = (_rule_name == "pep_api_mod_avu_metadata_pre" || _rule_name == "pep_api_atomic_apply_metadata_operations_pre");
        return SUCCESS();
    }

    auto list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules) -> irods::error
    {
        _rules.push_back("pep_api_atomic_apply_metadata_operations_pre");
        _rules.push_back("pep_api_mod_avu_metadata_pre");
        return SUCCESS();
    }

    auto exec_rule(irods::default_re_ctx&,
                   const std::string& _rule_name,
                   std::list<boost::any>& _rule_arguments,
                   irods::callback _effect_handler) -> irods::error
    {
        try {
            auto& rei = get_rei(_effect_handler);
            const auto config = load_plugin_config(rei);

            if (!config) {
                return CODE(RULE_ENGINE_CONTINUE);
            }

            if (_rule_name == "pep_api_atomic_apply_metadata_operations_pre") {
                // TODO Iterate over the list of operations and verify if any of them reference
                // AVUs within a protected namespace. Return an error if any of the AVUs is protected.
                const auto* bbuf = boost::any_cast<BytesBuf*>(*std::next(std::begin(_rule_arguments), 2));
                const auto json_input = json::parse(static_cast<const char*>(bbuf->buf), bbuf->len);

                for (auto&& op : json_input.at("operations")) {

                }
            }
            else { // pep_api_mod_avu_metadata_pre 
                const auto* input = boost::any_cast<modAVUMetadataInp_t*>(*std::next(std::begin(_rule_arguments), 2));

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
                for (auto&& prefix : config->at("prefixes")) {
                    // If the metadata attribute starts with the prefix, then verify that the user
                    // can modify the metadata attribute.
                    if (boost::starts_with(input->arg3, prefix.get_ref<const std::string&>())) {
                        // The "admin_only" flag supersedes the "editors" configuration option.
                        if (config->count("admin_only") && config->at("admin_only").get<bool>()) {
                            return user_is_administrator(*rei.rsComm);
                        }

                        namespace adm = irods::experimental::administration;

                        const adm::user user{rei.uoic->userName, rei.uoic->rodsZone};

                        for (auto&& editor : config->at("editors")) {
                            if (const auto& type = editor.at("type").get_ref<const std::string&>(); type == "group") {
                                const adm::group group{editor.at("name").get_ref<const std::string&>()};

                                if (adm::server::user_is_member_of_group(*rei.rsComm, group, user)) {
                                    return CODE(RULE_ENGINE_CONTINUE);
                                }
                            }
                            else if (type == "user") {
                                if (editor.at("name").get_ref<const std::string&>() == adm::server::local_unique_name(*rei.rsComm, user)) {
                                    return CODE(RULE_ENGINE_CONTINUE);
                                }
                            }
                        }

                        // At this point, the user is not an administrator and they aren't a member of
                        // the editors list. Therefore, we return an error because the user is attempting to
                        // modify metadata in a guarded namespace.
                        return ERROR(CAT_INSUFFICIENT_PRIVILEGE_LEVEL, "User is not allowed to modify metadata");
                    }
                }
            }
        }
        catch (const json::exception&) {
            // clang-format off
            log::rule_engine::error({{"log_message", "Unexpected JSON access or type error."},
                                     {"rule_engine_plugin", "metadata_guard"}});
            // clang-format on
        }
        catch (const std::exception& e) {
            log::rule_engine::error({{"log_message", e.what()}, {"rule_engine_plugin", "metadata_guard"}});
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

