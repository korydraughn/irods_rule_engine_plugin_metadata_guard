# iRODS Rule Engine Plugin - Metadata Guard

## Requirements
- iRODS v4.2.8+
- irods-dev package
- irods-runtime package
- irods-externals-boost package
- irods-externals-json package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_metadata_guard
$ cd irods_rule_engine_plugin_metadata_guard
$ git checkout 4-2-stable
$ mkdir _build && cd _build
$ cmake -GNinja ..
$ ninja package
```
After compiling, you should now have a `deb` or `rpm` package with a name similar to the following:
```bash
irods-rule-engine-plugin-metadata-guard-<plugin_version>-<os>-<arch>.<deb|rpm>
```

## Installing
Ubuntu:
```bash
$ sudo dpkg -i irods-rule-engine-plugin-metadata-guard-*.deb
```
CentOS:
```bash
$ su -c yum localinstall irods-rule-engine-plugin-metadata-guard-*.rpm
```
If the installation was successful, you should now have a new shared library. The full path to the library
should be similar to the following:
```
<irods_lib_home>/plugins/rule_engines/libirods_rule_engine_plugin-metadata_guard.so
```

## Configuration
The Rule Engine Plugin config is set as metadata on the **zone collection** (e.g. `/tempZone`).
Each option is explained below.
```javascript
{
    // The list of strings that represent metadata that should be guarded.
    // In this example, any metadata beginning with "irods::" will be treated special
    // and require that the user be an administrator or classified as an editor depending
    // on the configuration.
    "prefixes": ["irods::"],

    // Only administrators are allowed to modify metadata.
    // This option supersedes the "editors" option.
    "admin_only": true,

    // The list of editors that can modify guarded metadata.
    "editors": [
        {
            // The type of entity that is allowed to modify metadata.
            // The following options are available:
            // - "user"
            // - "group"
            "type": "group",

            // The name of the iRODS entity.
            // For remote users, you must include the zone (e.g. "rods#tempZone").
            "name": "rodsadmin"
        }
    ]
}
```
Once you've decided on what your config will be, you'll need to use `imeta` to set it. For example:
```bash
$ imeta set -C /tempZone irods::metadata_guard '{"prefixes": ["irods::"], "admin_only": true}'
```
Anytime a request to modify metadata is detected by the server, the Rule Engine Plugin will read the JSON
config and determine whether the user should be allowed to continue.

**NOTE: The user setting the metadata on the zone collection must have write permission on that collection!**

## Enabling the Rule Engine Plugin
To enable, add the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config should be placed before any rule engines that need metadata to be guarded.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-metadata_guard-instance",
        "plugin_name": "irods_rule_engine_plugin-metadata_guard",
        "plugin_specific_configuration": {}
    },
    
    // ... Previously installed Rule Engine Plugin configs ...
]

```

## Troubleshooting

### Q. What happens if the JSON configuration is incorrect (i.e. invalid JSON format)?
A. The log file will contain error messages saying the JSON config could not be parsed. Having a bad config can
be viewed as not having the metadata guard Rule Engine Plugin installed at all.

