from irods.access import iRODSAccess
from irods.session import iRODSSession
from irods.meta import iRODSMeta, AVUOperation

import irods.exception

import json
import os
import shutil
import tempfile
import unittest

class test_metadata_guard(unittest.TestCase):

    IRODS_CONFIG_FILE_PATH = '/etc/irods/server_config.json'
    TEST_DATA_OBJECT_PATH = '/tempZone/home/alice/test1'

    @classmethod
    def backup_irods_config(cls):
        cls.temp_path = os.path.join(tempfile.mkdtemp(), 'irods_config_backup')
        shutil.copy2(cls.IRODS_CONFIG_FILE_PATH, cls.temp_path)

    @classmethod
    def restore_irods_config(cls):
        shutil.copy2(cls.temp_path,cls.IRODS_CONFIG_FILE_PATH)

    @classmethod
    def setUpClass(cls):
        with iRODSSession(host='localhost', port=1247, user='rods', password='rods', zone='tempZone') as local_admin:
            # create unprivileged user
            local_admin.users.create_with_password('alice', 'test')

            # unprivileged user creates test file
            with iRODSSession(host='localhost', port=1247, user='alice', password='test', zone='tempZone') as unprivileged_user:
                unprivileged_user.data_objects.create(cls.TEST_DATA_OBJECT_PATH)
                unprivileged_user.acls.set( iRODSAccess('own', cls.TEST_DATA_OBJECT_PATH, 'rods', 'tempZone'))

            coll = local_admin.collections.get("/tempZone")
            # add metadata_guard config AVU to collection
            METADATA_GUARD_CONFIG = {
                'admin_only': True,
                'prefixes': ['irods::']
            }
            if 'irods::metadata_guard' not in coll.metadata:
                coll.metadata.add('irods::metadata_guard', json.dumps(METADATA_GUARD_CONFIG))

            # create backup of irods config file
            cls.backup_irods_config()
            # insert metadata guard rule engine plugin to irods config file
            with open(cls.IRODS_CONFIG_FILE_PATH, 'r+') as config_file:
                METADATA_GUARD_PLUGIN_BLOCK = {
                    'instance_name': 'irods_rule_engine_plugin-metadata_guard-instance',
                    'plugin_name': 'irods_rule_engine_plugin-metadata_guard',
                    'plugin_specific_configuration': {}
                }
                config_json = json.load(config_file)
                config_json['plugin_configuration']['rule_engines'].insert(0, METADATA_GUARD_PLUGIN_BLOCK)
            with open(cls.IRODS_CONFIG_FILE_PATH, 'wt') as config_file:
                json.dump(config_json, config_file)

    @classmethod
    def tearDownClass(cls):
        cls.restore_irods_config()

    def test_guard_atomic_bad_config__issue_38(self):
        # set metadata_guard config AVU on collection to nonsense
        with iRODSSession(host='localhost', port=1247, user='rods', password='rods', zone='tempZone') as local_admin:
            coll = local_admin.collections.get("/tempZone")
            coll.metadata['irods::metadata_guard'] = iRODSMeta('irods::metadata_guard', '{"broken": ["irods::"], ')

        with iRODSSession(host='localhost', port=1247, user='alice', password='test', zone='tempZone') as unprivileged_user:
            obj = unprivileged_user.data_objects.get(self.TEST_DATA_OBJECT_PATH)
            obj.metadata.apply_atomic_operations( AVUOperation(operation='add', avu=iRODSMeta('irods::badconfig','badconfig')))

            # bad config means operation should succeed
            self.assertEqual(obj.metadata['irods::badconfig'], iRODSMeta('irods::badconfig', 'badconfig'))
            obj.metadata.apply_atomic_operations( AVUOperation(operation='remove', avu=iRODSMeta('irods::badconfig','badconfig')))

    def test_guard_atomic_operations_admin_only__issue_38(self):
        # set metadata_guard config AVU on collection to admin_only and irods:: as protected prefix
        with iRODSSession(host='localhost', port=1247, user='rods', password='rods', zone='tempZone') as local_admin:
            coll = local_admin.collections.get("/tempZone")
            METADATA_GUARD_CONFIG = {
                'admin_only': True,
                'prefixes': ['irods::']
            }
            coll.metadata['irods::metadata_guard'] = iRODSMeta('irods::metadata_guard', json.dumps(METADATA_GUARD_CONFIG))

            obj = local_admin.data_objects.get(self.TEST_DATA_OBJECT_PATH)
            obj.metadata.apply_atomic_operations( AVUOperation(operation='add', avu=iRODSMeta('irods::adminonly','adminonly')))
            
            # admin should still be allowed to add metadata
            self.assertEqual(obj.metadata['irods::adminonly'], iRODSMeta('irods::adminonly', 'adminonly'))

        with iRODSSession(host='localhost', port=1247, user='alice', password='test', zone='tempZone') as unprivileged_user:
            obj = unprivileged_user.data_objects.get(self.TEST_DATA_OBJECT_PATH)

            # "unguarded::" not protected, so operation should succeed
            obj.metadata.apply_atomic_operations( AVUOperation(operation='add', avu=iRODSMeta('unguarded::atr1','val1')))
            self.assertEqual(obj.metadata['unguarded::atr1'], iRODSMeta('unguarded::atr1', 'val1'))

            # "irods::" protected, so metadata add should fail
            self.assertRaises(irods.exception.CAT_INSUFFICIENT_PRIVILEGE_LEVEL, lambda: obj.metadata.apply_atomic_operations( AVUOperation(operation='add', avu=iRODSMeta('irods::atr','val'))))

            # "irods::" protected, so metadata delete should fail
            self.assertRaises(irods.exception.CAT_INSUFFICIENT_PRIVILEGE_LEVEL, lambda: obj.metadata.apply_atomic_operations( AVUOperation(operation='remove', avu=iRODSMeta('irods::adminonly','adminonly'))))

    def test_guard_atomic_operations_editor_list__issue_38(self):
        # set metadata_guard config AVU on collection to admin_only: false and irods:: as protected prefix
        # also, add alice user as editor
        with iRODSSession(host='localhost', port=1247, user='rods', password='rods', zone='tempZone') as local_admin:
            coll = local_admin.collections.get("/tempZone")
            METADATA_GUARD_CONFIG = {
                'admin_only': False,
                'editors': [{'name': 'rods', 'type': 'user'}, {'name': 'alice', 'type': 'user'}],
                'prefixes': ['irods::']
            }
            coll.metadata['irods::metadata_guard'] = iRODSMeta('irods::metadata_guard', json.dumps(METADATA_GUARD_CONFIG))

        with iRODSSession(host='localhost', port=1247, user='alice', password='test', zone='tempZone') as unprivileged_user:
            obj = unprivileged_user.data_objects.get(self.TEST_DATA_OBJECT_PATH)

            # operation should succeed, as alice is set as an editor
            obj.metadata.apply_atomic_operations( AVUOperation(operation='add', avu=iRODSMeta('irods::editorlist', 'editorlist')))
            self.assertEqual(obj.metadata['irods::editorlist'], iRODSMeta('irods::editorlist', 'editorlist'))

        # remove alice user from editor list
        with iRODSSession(host='localhost', port=1247, user='rods', password='rods', zone='tempZone') as local_admin:
            coll = local_admin.collections.get("/tempZone")
            METADATA_GUARD_CONFIG = {
                'admin_only': False,
                'editors': [{'name': 'rods', 'type': 'user'}],
                'prefixes': ['irods::']
            }
            coll.metadata['irods::metadata_guard'] = iRODSMeta('irods::metadata_guard', json.dumps(METADATA_GUARD_CONFIG))

        with iRODSSession(host='localhost', port=1247, user='alice', password='test', zone='tempZone') as unprivileged_user:
            obj = unprivileged_user.data_objects.get(self.TEST_DATA_OBJECT_PATH)

            # this was set previously, make sure it is still the case
            self.assertEqual(obj.metadata['irods::editorlist'], iRODSMeta('irods::editorlist', 'editorlist'))
            # operation should fail, as test user is no longer in editor list
            self.assertRaises(irods.exception.CAT_INSUFFICIENT_PRIVILEGE_LEVEL, lambda: obj.metadata.apply_atomic_operations( AVUOperation(operation='remove', avu=iRODSMeta('irods::editorlist', 'editorlist'))))


if __name__ == '__main__':
    unittest.main()
