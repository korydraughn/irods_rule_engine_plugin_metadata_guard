# iRODS Rule Engine Plugin - Metadata Guard

## Requirements
- iRODS v4.3.0+
- irods-dev package
- irods-runtime package
- irods-externals-boost package
- irods-externals-json package

## Compiling
```bash
$ git clone https://github.com/irods/irods_rule_engine_plugin_metadata_guard
$ cd irods_rule_engine_plugin_metadata_guard
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
Enabling this rule engine plugin requires two steps:
1. Use `imeta` to set the necessary JSON configuration on the root collection (e.g. /tempZone).
2. Add the rule engine plugin to `server_config.json`.

### Step 1 - JSON Configuration
Set JSON configuration on the root collection (e.g. /tempZone). Any time a request to modify metadata is detected
by the server, the rule engine plugin will read this JSON configuration and determine whether the user should be
allowed to continue.
```bash
$ imeta set -C /<zone_name> irods::metadata_guard '{"admin_only": true}'
```

### Step 2 - server_config.json
To enable, prepend the following plugin config to the list of rule engines in `/etc/irods/server_config.json`. 
The plugin config should be placed near the beginning of the `"rule_engines"` section.

Even though this plugin will process PEPs first due to it's positioning, subsequent Rule Engine Plugins (REP) will 
still be allowed to process the same PEPs without any issues.
```javascript
"rule_engines": [
    {
        "instance_name": "irods_rule_engine_plugin-metadata_guard-instance",
        "plugin_name": "irods_rule_engine_plugin-metadata_guard",
        "plugin_specific_configuration": {}
    },
    
    // ... Previously installed rule engine plugin configs ...
]

```
## Usage

