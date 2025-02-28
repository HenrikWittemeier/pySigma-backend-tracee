import os
import glob
import sys
skipped_products = [
    "windows",
    "macos",
    "jvm",
    "nodejs",
    "django",
    "m365",
    "azure",
    "okta",
    "fortios",
    "paloalto",
    "opencanary",
    "python",
    "kubernetes",
    "ruby_on_rails",
    "velocity",
    "rpc_firewall",
    "spring",
    "aws",
    "gcp",
    "onelogin",
    "cisco",
    "github",
    "bitbucket",
    "huawei",
    "juniper",
    "zeek",
    "qualys"
]
skipped_services = [
    "auditd",
    "syslog",
    "netflow",
    "nginx",
    "apache",
    "guacamole",
    "sudo",
    "clamav",
    "auth",
    "cron",
    "sshd",
    "vsftpd",
    ""
]
skipped_categories = [
    "antivirus",
    "database",
    ""
]
import sigma.exceptions
from sigma.collection import SigmaCollection
from sigma.backends.tracee import tracee
if len(sys.argv)>1:
    rule_dir = sys.argv[1]
else:
    rule_dir = "../sigma"
process_start_rules = []

for filename in glob.iglob(rule_dir+'/rules*/**/*.yml', recursive=True):
     process_start_rules.append(f"{filename}")


tracee_backend = tracee.TraceeBackend()

process_start_rule_collection = SigmaCollection.load_ruleset(process_start_rules)

counter_all = 0
counter_usefull = 0
counter_compiled = 0


for rule in process_start_rule_collection.rules:
    if rule.logsource.product in skipped_products or rule.logsource.service in skipped_services or rule.logsource.category in skipped_categories:
        counter_all = counter_all+1
        continue
    print("__________________________________________")
    print(rule.title + " conversion:")
    counter_usefull = counter_usefull+1
    try:
        rule_converted = tracee_backend.convert_rule(rule)[0]
        with open("tracee_signatures/"+rule.source.path.name.replace(".yml",".go"),"w") as file:
            file.write(rule_converted)
        counter_compiled = counter_compiled+1
    except sigma.exceptions.SigmaTransformationError:
        print("Logsource not implemented")
        print(rule.logsource)
    except BaseException:
        pass

print(f"Found {counter_all} Sigma rules.\nAttempted to compile {counter_usefull} rules.\nSuccessfull where {counter_compiled} Rules")