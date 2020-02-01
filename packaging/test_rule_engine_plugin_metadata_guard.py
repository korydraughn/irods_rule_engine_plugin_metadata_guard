from __future__ import print_function

import os
import sys
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
users  = [('alice', 'rods')]

class Test_Rule_Engine_Plugin_Metadata_Guard(session.make_sessions_mixin(admins, users), unittest.TestCase):

    def setUp(self):
        super(Test_Rule_Engine_Plugin_Metadata_Guard, self).setUp()
        self.rods = session.make_session_for_existing_admin()
        self.admin = self.admin_sessions[0]
        self.user = self.user_sessions[0]

    def tearDown(self):
        super(Test_Rule_Engine_Plugin_Metadata_Guard, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_incorrect_configuration_does_not_block_usage(self):
	config = IrodsConfig()

        # Set invalid JSON configuration for the root collection.
        root_coll = os.path.join('/', self.admin.zone_name)
        json_config = '{bad JSON config}'
        self.rods.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

        # The number of times the expected error message is seen in the log file.
        count = 0

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            # This should cause an exception to be thrown and logged, but users
            # should still be able to proceed. Verify that the log contains a valid
            # error message.
            log_offset = lib.get_file_size_by_path(paths.server_log_path())
            self.rods.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])
            count = lib.count_occurrences_of_string_in_log(paths.server_log_path(), 'Cannot parse Rule Engine Plugin configuration', log_offset)

        # Clean up.
        self.rods.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

        self.assertTrue(count > 0)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_users_can_modify_guarded_metadata(self):
	config = IrodsConfig()

        # Set JSON configuration for the root collection.
        root_coll = os.path.join('/', self.admin.zone_name)
        json_config = json.dumps({
            'prefixes': ['irods::'],
            'admin_only': False,
            'editors': [
                {'type': 'group', 'name': 'rodsadmin'},
                {'type': 'user',  'name': self.admin.username},
                {'type': 'user',  'name': self.user.username}
            ]
        })
        self.rods.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

        with lib.file_backed_up(config.server_config_path):
            self.enable_rule_engine_plugin(config)

            coll = self.admin.session_collection
            attribute_name = 'irods::guarded_attribute'
            self.admin.assert_icommand(['imeta', 'set', '-C', coll, attribute_name, 'abc'])
            self.admin.assert_icommand(['ichmod', 'write', self.user.username, coll])

            new_attr_value = 'DEF'
            self.user.assert_icommand(['imeta', 'set', '-C', coll, attribute_name, new_attr_value])
            self.admin.assert_icommand(['imeta', 'rm', '-C', coll, attribute_name, new_attr_value])

        # Clean up.
        self.rods.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_users_cannot_modify_guarded_metadata(self):
	config = IrodsConfig()

        root_coll = os.path.join('/', self.admin.zone_name)
        json_configs = [
            json.dumps({
                'prefixes': ['irods::'],
                'admin_only': True
            }),
            json.dumps({
                'prefixes': ['irods::'],
                'editors': [
                    {'type': 'user', 'name': self.rods.username},
                    {'type': 'user', 'name': self.admin.username}
                ]
            }),
            json.dumps({
                'prefixes': ['irods::'],
                'editors': [
                    {'type': 'group', 'name': 'rodsadmin'}
                ]
            })
        ]

        self.rods.assert_icommand(['iadmin', 'atg', 'rodsadmin', self.admin.username])

        for json_config in json_configs:
            # Set JSON configuration for the root collection.
            self.rods.assert_icommand(['imeta', 'set', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

            with lib.file_backed_up(config.server_config_path):
                self.enable_rule_engine_plugin(config)

                coll = self.admin.session_collection
                attribute_name = 'irods::guarded_attribute'
                self.admin.assert_icommand(['imeta', 'set', '-C', coll, attribute_name, 'abc'])
                self.admin.assert_icommand(['ichmod', 'write', self.user.username, coll])

                self.user.assert_icommand(['imeta', 'set', '-C', coll, attribute_name, 'DEF'], 'STDERR', ['CAT_INSUFFICIENT_PRIVILEGE_LEVEL'])

            # Clean up.
            self.rods.assert_icommand(['imeta', 'rm', '-C', root_coll, self.metadata_guard_attribute_name(), json_config])

        self.rods.assert_icommand(['iadmin', 'rfg', 'rodsadmin', self.admin.username])

    #
    # Utility Functions
    #

    def enable_rule_engine_plugin(self, config):
        config.server_config['log_level']['rule_engine'] = 'trace'
        config.server_config['log_level']['legacy'] = 'trace'
        config.server_config['plugin_configuration']['rule_engines'].insert(0, {
            'instance_name': 'irods_rule_engine_plugin-metadata_guard-instance',
            'plugin_name': 'irods_rule_engine_plugin-metadata_guard',
            'plugin_specific_configuration': {}
        })
        lib.update_json_file_from_dict(config.server_config_path, config.server_config)

    def metadata_guard_attribute_name(self):
        return 'irods::metadata_guard'

