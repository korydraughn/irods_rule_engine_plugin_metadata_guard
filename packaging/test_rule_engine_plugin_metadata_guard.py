from __future__ import print_function

import os
import sys
import shutil
import json

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig

admins = [('otherrods', 'rods')]
users  = [('otheralice', 'rods')]

class Test_Rule_Engine_Plugin_Metadata_Guard(session.make_sessions_mixin(admins, users), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Metadata_Guard, self).setUp()
        self.admin = self.admin_sessions[0]
        self.user = self.user_sessions[0]

    def tearDown(self):
        super(Test_Rule_Engine_Plugin_Metadata_Guard, self).tearDown()

    # TODO Test incorrect REP configuration does not block iRODS usage.
    # TODO Test users can modify guarded metadata (admin_only vs prefix + editors).
    # TODO Test users cannot modify guarded metadata (admin_only vs prefix + editors).

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_incorrect_configuration_does_not_block_usage(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Set invalid JSON configuration for the root collection.
            root_coll = os.path.join('/', self.admin.zone_name)
            json_config = 'bad JSON config'
            self.admin.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

            # This should cause an exception to be thrown and logged, but users
            # should still be able to proceed. Verify that the log contains a valid
            # error message.
            start_index = lib.get_file_size_by_path(paths.server_log_path())
            self.admin.assert_icommand(['ils'], 'STDOUT', [self.admin.local_session_dir])
            count = lib.count_occurrences_of_string_in_log(paths.server_log_path(), 'Cannot parse Rule Engine Plugin configuration', start_index)
            self.assertEqual(count, 1)

            # Clean up.
            self.admin.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_users_can_modify_guarded_metadata(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Set JSON configuration for the root collection.
            root_coll = os.path.join('/', self.admin.zone_name)
            json_config = json.dumps({
                "prefixes": ["irods::"],
                "editors": [
                    {"type": "user", "name": "otherrods"},
                    {"type": "user", "name": "otheralice"}
                ]
            })
            self.admin.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])
            self.admin.assert_icommand(['imeta', 'set', '-C', self.admin.local_session_dir, 'irods::guarded_attr', 'abc'])

            # Give write permission to less privileged user.
            self.admin.assert_icommand(['ichmod', 'write', 'otheralice', self.admin.local_session_dir])
            self.user.assert_icommand(['imeta', 'set', '-C', self.admin.local_session_dir, 'irods::guarded_attr', 'DEF'])

            # Clean up.
            self.admin.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_users_cannot_modify_guarded_metadata(self):
	config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # Set JSON configuration for the root collection.
            root_coll = os.path.join('/', self.admin.zone_name)
            json_config = json.dumps({
                "prefixes": ["irods::"],
                "editors": [
                    {"type": "user", "name": "otherrods"}
                ]
            })
            self.admin.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])
            self.admin.assert_icommand(['imeta', 'set', '-C', self.admin.local_session_dir, 'irods::guarded_attr', 'abc'])

            # Give write permission to less privileged user.
            self.admin.assert_icommand(['ichmod', 'write', 'otheralice', self.admin.local_session_dir])
            self.user.assert_icommand(['imeta', 'set', '-C', self.admin.local_session_dir, 'irods::guarded_attr', 'DEF'],
                                      'STDERR', ['CAT_INSUFFICIENT_PRIVILEGE_LEVEL'])

            # Clean up.
            self.admin.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

    #
    # Utility Functions
    #

    def enable_rule_engine_plugin(self, config):
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-metadata_guard-instance',
            'plugin_name': 'irods_rule_engine_plugin-metadata_guard',
            'plugin_specific_configuration': {}
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def metadata_guard_attribute_name(self):
        return 'irods::metadata_guard'

