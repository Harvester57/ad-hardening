import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

userright_mapping = {
    'SeDenyInteractiveLogonRight': 'SE_DENY_INTERACTIVE_LOGON_NAME',
    'SeDenyNetworkLogonRight': 'SE_DENY_NETWORK_LOGON_NAME',
    'SeDenyRemoteInteractiveLogonRight': 'SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME',
    'SeDenyServiceLogonRight': 'SE_DENY_SERVICE_LOGON_NAME',
    'SeDenyBatchLogonRight': 'SE_DENY_BATCH_LOGON_NAME',
    'SeInteractiveLogonRight': 'SE_INTERACTIVE_LOGON_NAME',
    'SeNetworkLogonRight': 'SE_NETWORK_LOGON_NAME',
    'SeRemoteInteractiveLogonRight': 'SE_REMOTE_INTERACTIVE_LOGON_NAME',
    'SeServiceLogonRight': 'SE_SERVICE_LOGON_NAME',
    'SeBatchLogonRight': 'SE_BATCH_LOGON_NAME',
    'SeAssignPrimaryTokenPrivilege': 'SE_ASSIGNPRIMARYTOKEN_NAME',
    'SeAuditPrivilege': 'SE_AUDIT_NAME',
    'SeBackupPrivilege': 'SE_BACKUP_NAME',
    'SeChangeNotifyPrivilege': 'SE_CHANGE_NOTIFY_NAME',
    'SeCreateGlobalPrivilege': 'SE_CREATE_GLOBAL_NAME',
    'SeCreatePagefilePrivilege': 'SE_CREATE_PAGEFILE_NAME',
    'SeCreatePermanentPrivilege': 'SE_CREATE_PERMANENT_NAME',
    'SeCreateSymbolicLinkPrivilege': 'SE_CREATE_SYMBOLIC_LINK_NAME',
    'SeCreateTokenPrivilege': 'SE_CREATE_TOKEN_NAME',
    'SeDebugPrivilege': 'SE_DEBUG_NAME',
    'SeEnableDelegationPrivilege': 'SE_ENABLE_DELEGATION_NAME',
    'SeImpersonatePrivilege': 'SE_IMPERSONATE_NAME',
    'SeIncreaseBasePriorityPrivilege': 'SE_INC_BASE_PRIORITY_NAME',
    'SeIncreaseQuotaPrivilege': 'SE_INCREASE_QUOTA_NAME',
    'SeIncreaseWorkingSetPrivilege': 'SE_INC_WORKING_SET_NAME',
    'SeLoadDriverPrivilege': 'SE_LOAD_DRIVER_NAME',
    'SeLockMemoryPrivilege': 'SE_LOCK_MEMORY_NAME',
    'SeMachineAccountPrivilege': 'SE_MACHINE_ACCOUNT_NAME',
    'SeManageVolumePrivilege': 'SE_MANAGE_VOLUME_NAME',
    'SeProfileSingleProcessPrivilege': 'SE_PROF_SINGLE_PROCESS_NAME',
    'SeRelabelPrivilege': 'SE_RELABEL_NAME',
    'SeRemoteShutdownPrivilege': 'SE_REMOTE_SHUTDOWN_NAME',
    'SeRestorePrivilege': 'SE_RESTORE_NAME',
    'SeSecurityPrivilege': 'SE_SECURITY_NAME',
    'SeShutdownPrivilege': 'SE_SHUTDOWN_NAME',
    'SeSyncAgentPrivilege': 'SE_SYNC_AGENT_NAME',
    'SeSystemEnvironmentPrivilege': 'SE_SYSTEM_ENVIRONMENT_NAME',
    'SeSystemProfilePrivilege': 'SE_SYSTEM_PROFILE_NAME',
    'SeSystemtimePrivilege': 'SE_SYSTEMTIME_NAME',
    'SeTakeOwnershipPrivilege': 'SE_TAKE_OWNERSHIP_NAME',
    'SeTcbPrivilege': 'SE_TCB_NAME',
    'SeTimeZonePrivilege': 'SE_TIME_ZONE_NAME',
    'SeTrustedCredManAccessPrivilege': 'SE_TRUSTED_CREDMAN_ACCESS_NAME',
    'SeUndockPrivilege': 'SE_UNDOCK_NAME',
    'SeUnsolicitedInputPrivilege': 'SE_UNSOLICITED_INPUT_NAME'
}

def parse_dsc_profiles(dsc_path):
    """
    Parses dsc/ADHardeningAudit.ps1 to extract lists of audit scripts
    assigned to common, DomainController, PAW, and Endpoint profiles.
    """
    if not os.path.exists(dsc_path):
        print(f"Warning: DSC configuration file not found at {dsc_path}")
        return [], [], [], []
        
    with open(dsc_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Regex matching lists like: $commonScripts = @(...)
    common_match = re.search(r'\$commonScripts\s*=\s*@\((.*?)\)', content, re.DOTALL)
    dc_match = re.search(r'if\s*\(\$Profile\s*-eq\s*"DomainController"\)\s*\{\s*\$profileScripts\s*=\s*@\((.*?)\)', content, re.DOTALL)
    paw_match = re.search(r'elseif\s*\(\$Profile\s*-eq\s*"PAW"\)\s*\{\s*\$profileScripts\s*=\s*@\((.*?)\)', content, re.DOTALL)
    endpoint_match = re.search(r'else\s*\{\s*(?:#\s*Endpoint profile\s*)?\$profileScripts\s*=\s*@\((.*?)\)', content, re.DOTALL)
    
    path_regex = re.compile(r'["\']([^"\']+\.ps1)["\']')
    
    common_scripts = []
    dc_scripts = []
    paw_scripts = []
    endpoint_scripts = []
    
    if common_match:
        common_scripts = [p.replace('\\', '/') for p in path_regex.findall(common_match.group(1))]
    if dc_match:
        dc_scripts = [p.replace('\\', '/') for p in path_regex.findall(dc_match.group(1))]
    if paw_match:
        paw_scripts = [p.replace('\\', '/') for p in path_regex.findall(paw_match.group(1))]
    if endpoint_match:
        endpoint_scripts = [p.replace('\\', '/') for p in path_regex.findall(endpoint_match.group(1))]
        
    return common_scripts, dc_scripts, paw_scripts, endpoint_scripts

def get_basename(path):
    return os.path.basename(path).lower() if path else ""

def normalize_reg_check(key_path, name, vtype, val):
    # Standardize hive and remove it from path
    hive = 'HKEY_LOCAL_MACHINE'
    key = key_path.strip()
    
    key_upper = key.upper()
    if key_upper.startswith('HKCU') or 'HKEY_CURRENT_USER' in key_upper:
        hive = 'HKEY_CURRENT_USER'
        key = key.replace('HKCU:\\', '').replace('HKCU:', '').replace('HKCU\\', '').replace('HKEY_CURRENT_USER\\', '').strip('\\')
    elif key_upper.startswith('HKU') or 'HKEY_USERS' in key_upper:
        hive = 'HKEY_USERS'
        key = key.replace('HKU:\\', '').replace('HKU:', '').replace('HKU\\', '').replace('HKEY_USERS\\', '').strip('\\')
    elif key_upper.startswith('HKCR') or 'HKEY_CLASSES_ROOT' in key_upper:
        hive = 'HKEY_CLASSES_ROOT'
        key = key.replace('HKCR:\\', '').replace('HKCR:', '').replace('HKCR\\', '').replace('HKEY_CLASSES_ROOT\\', '').strip('\\')
    else:
        key = key.replace('HKLM:\\', '').replace('HKLM:', '').replace('HKLM\\', '').replace('HKEY_LOCAL_MACHINE\\', '').strip('\\')

    name = name.strip()
    vtype = vtype.strip().upper()
    data = val.strip()
    
    op = 'equals'
    if '>=' in data:
        op = 'greater than or equal'
    elif '<=' in data:
        op = 'less than or equal'
    elif '>' in data:
        op = 'greater than'
    elif '<' in data:
        op = 'less than'
        
    if 'DWORD' in vtype or vtype in ['0XFF', '1', '0', 'REG_DWORD']:
        vtype = 'REG_DWORD'
    elif 'SZ' in vtype:
        vtype = 'REG_SZ'
    elif 'BINARY' in vtype:
        vtype = 'REG_BINARY'
    else:
        # Default based on data shape
        if data.isdigit() or data.lower().startswith('0x') or any(o in data for o in ['>=', '<=', '>', '<']):
            vtype = 'REG_DWORD'
        else:
            vtype = 'REG_SZ'
            
    # Clean value based on type
    if vtype == 'REG_DWORD':
        if data.lower().startswith('0x') or ('0x' in data.lower()):
            hex_match = re.search(r'0x[a-fA-F0-9]+', data)
            if hex_match:
                try:
                    data = str(int(hex_match.group(0), 16))
                except ValueError:
                    data = '1'
            else:
                data = '1'
        else:
            data_digits = re.search(r'\d+', data)
            if data_digits:
                data = data_digits.group(0)
            else:
                data = '1'
    elif vtype == 'REG_SZ':
        if data.startswith('"') and data.endswith('"'):
            data = data[1:-1]
        elif data.startswith("'") and data.endswith("'"):
            data = data[1:-1]
            
    is_delete = False
    if 'delete' in data.lower() or 'not configured' in data.lower():
        is_delete = True
        
    res = {
        'hive': hive,
        'key': key,
        'name': name,
        'type': vtype.lower(),
        'data': data,
        'operation': op
    }
    if is_delete:
        res['existence'] = 'none_exist'
        
    return res

subcat_mapping = {
    'audit kerberos authentication service': 'kerberos_authentication_service',
    'audit kerberos service ticket operations': 'kerberos_service_ticket_operations',
    'audit credential validation': 'credential_validation',
    'audit user account management': 'user_account_management',
    'audit security group management': 'security_group_management',
    'audit application group management': 'application_group_management',
    'audit computer account management': 'computer_account_management',
    'audit distribution group management': 'distribution_group_management',
    'audit other account management events': 'other_account_management_events',
    'audit process creation': 'process_creation',
    'audit dpapi activity': 'dpapi_activity',
    'audit pnp activity': 'pnp_activity',
    'audit directory service changes': 'directory_service_changes',
    'audit directory service access': 'directory_service_access',
    'audit logon': 'logon',
    'audit logoff': 'logoff',
    'audit special logon': 'special_logon',
    'audit account lockout': 'account_lockout',
    'audit other logon/logoff events': 'other_logon_logoff_events',
    'audit handle manipulation': 'handle_manipulation',
    'audit registry': 'registry',
    'audit file share': 'file_share',
    'audit detailed file share': 'detailed_file_share',
    'audit other object access events': 'other_object_access_events',
    'audit policy change': 'audit_policy_change',
    'audit authentication policy change': 'authentication_policy_change',
    'audit authorization policy change': 'authorization_policy_change',
    'audit mpssvc rule-level policy change': 'mpssvc_rule_level_policy_change',
    'audit other policy change events': 'other_policy_change_events',
    'audit sensitive privilege use': 'sensitive_privilege_use',
    'audit ipsec driver': 'ipsec_driver',
    'audit other system events': 'other_system_events',
    'audit security state change': 'security_state_change',
    'audit security system extension': 'security_system_extension',
    'audit system integrity': 'system_integrity'
}

def parse_ps1_for_registry_and_services(script_content):
    registry_checks = []
    service_checks = []
    
    # 1. Extract variables representing registry paths and values
    var_defs = {}
    val_defs = {}
    
    # Path variables (usually HKLM/HKCU)
    var_matches = re.finditer(r'\$([a-zA-Z0-9_]+)\s*=\s*["\']((?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[^"\']+)["\']', script_content, re.IGNORECASE)
    for m in var_matches:
        var_name = m.group(1)
        val_path = m.group(2).replace(':', '')
        var_defs[var_name] = val_path
        
    # Value variables (strings or integers)
    val_matches = re.finditer(r'\$([a-zA-Z0-9_]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([0-9]+))', script_content)
    for m in val_matches:
        var_name = m.group(1)
        val_value = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if val_value is not None:
            val_defs[var_name] = val_value
        
    # 2. Extract Set-ItemProperty / New-ItemProperty calls
    set_prop_pattern = r'(?:Set-ItemProperty|New-ItemProperty)\s+-Path\s+(\$[a-zA-Z0-9_]+|"[^"]+"|\'[^\']+\')\s+-Name\s+("[^"]+"|\'[^\']+\'|[a-zA-Z0-9_]+)\s+-Value\s+("[^"]+"|\'[^\']+\'|[a-zA-Z0-9_]+|[0-9]+|\$[a-zA-Z0-9_]+)'
    for m in re.finditer(set_prop_pattern, script_content, re.IGNORECASE):
        path_raw = m.group(1).strip()
        name_raw = m.group(2).strip().strip('"\'')
        value_raw = m.group(3).strip().strip('"\'')
        
        path = ""
        if path_raw.startswith('$'):
            var_name = path_raw[1:]
            path = var_defs.get(var_name, "")
        else:
            path = path_raw.strip('"\'').replace(':', '')
            
        if value_raw.startswith('$'):
            var_name = value_raw[1:]
            value_raw = val_defs.get(var_name, value_raw)
            
        if path and name_raw:
            line_start = script_content.rfind('\n', 0, m.start()) + 1
            line_end = script_content.find('\n', m.end())
            if line_end == -1:
                line_end = len(script_content)
            line = script_content[line_start:line_end]
            
            vtype = "UNKNOWN"
            if "-Type DWord" in line or "-Type dword" in line:
                vtype = "REG_DWORD"
            elif "-Type MultiString" in line or "-Type multistring" in line:
                vtype = "REG_MULTI_SZ"
            elif "-Type String" in line or "-Type string" in line:
                vtype = "REG_SZ"
                
            if vtype == "UNKNOWN":
                if value_raw.isdigit():
                    vtype = "REG_DWORD"
                else:
                    vtype = "REG_SZ"
                    
            chk = normalize_reg_check(path, name_raw, vtype, value_raw)
            if not any(c['key'] == chk['key'] and c['name'] == chk['name'] and c['hive'] == chk['hive'] for c in registry_checks):
                registry_checks.append(chk)
            
    # 3. Extract custom helper functions
    custom_helpers = [('Set-RegDWord', 'REG_DWORD'), ('Set-RegString', 'REG_SZ'), ('Set-RegMultiString', 'REG_MULTI_SZ')]
    for helper_name, vtype in custom_helpers:
        helper_pattern = rf'{helper_name}\s+("[^"]+"|\'[^\']+\'|\$[a-zA-Z0-9_]+)\s+("[^"]+"|\'[^\']+\')\s+("[^"]+"|\'[^\']+\'|\$[a-zA-Z0-9_]+|[a-zA-Z0-9_]+|[0-9]+)'
        for m in re.finditer(helper_pattern, script_content, re.IGNORECASE):
            path_raw = m.group(1).strip()
            name_raw = m.group(2).strip().strip('"\'')
            value_raw = m.group(3).strip().strip('"\'')
            
            path = ""
            if path_raw.startswith('$'):
                var_name = path_raw[1:]
                path = var_defs.get(var_name, "")
            else:
                path = path_raw.strip('"\'').replace(':', '')
                
            if value_raw.startswith('$'):
                var_name = value_raw[1:]
                value_raw = val_defs.get(var_name, value_raw)
                
            if path and name_raw:
                chk = normalize_reg_check(path, name_raw, vtype, value_raw)
                if not any(c['key'] == chk['key'] and c['name'] == chk['name'] and c['hive'] == chk['hive'] for c in registry_checks):
                    registry_checks.append(chk)
                
    # 4. Extract Set-Service calls
    service_pattern = r'Set-Service\s+(?:-Name\s+)?("[^"]+"|\'[^\']+\'|[a-zA-Z0-9_]+)\s+-StartupType\s+(\w+)'
    for m in re.finditer(service_pattern, script_content, re.IGNORECASE):
        svc_name = m.group(1).strip().strip('"\'')
        startup_type = m.group(2).strip().upper()
        
        start_type_map = {
            'DISABLED': 'SERVICE_DISABLED',
            'AUTOMATIC': 'SERVICE_AUTO_START',
            'MANUAL': 'SERVICE_DEMAND_START'
        }
        if not any(s['service_name'].lower() == svc_name.lower() for s in service_checks):
            service_checks.append({
                'service_name': svc_name,
                'start_type': start_type_map.get(startup_type, 'SERVICE_DISABLED')
            })
        
    # 5. Extract array of services from loop-based service scripts
    array_match = re.search(r'\$Services\s*=\s*@\((.*?)\r?\n\s*\)', script_content, re.DOTALL | re.IGNORECASE)
    if array_match:
        array_content = array_match.group(1)
        for name in re.findall(r'["\']([a-zA-Z0-9_-]+)["\']', array_content):
            if not any(s['service_name'].lower() == name.lower() for s in service_checks):
                service_checks.append({
                    'service_name': name,
                    'start_type': 'SERVICE_DISABLED'
                })
            
    return registry_checks, service_checks

def scan_markdown_requirements(repo_root, common_scripts, dc_scripts, paw_scripts, endpoint_scripts):
    """
    Scans the repository for requirement markdown files and builds metadata list.
    """
    requirements = []
    exclude_dirs = {'.git', '.gemini', '_book', 'node_modules', 'compliance', 'styles', 'plugins', 'dsc', 'scripts'}
    
    # Group requirements by prefix to establish module names
    prefix_to_module = {
        'ARCH': 'Module 1: Architecture & Administrative Tiering',
        'DC': 'Module 2: Domain Controller Hardening',
        'ID': 'Module 3: Identities & Services Hardening',
        'NET': 'Module 4: Network Configuration & Firewalling',
        'LOG': 'Module 5: Logging, Monitoring & SIEM',
        'OPS': 'Module 6: Secure Operations & Maintenance',
        'PAW': 'Module 7: Privileged Access Workstations (PAWs) Hardening',
        'END': 'Module 8: Endpoint Hardening'
    }
    
    prefix_to_int = {
        'ARCH': 1000,
        'DC': 2000,
        'ID': 3000,
        'NET': 4000,
        'LOG': 5000,
        'OPS': 6000,
        'PAW': 7000,
        'END': 8000
    }
    
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith('.md') and not file.startswith('README') and not file.lower().startswith('template'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo_root)
                
                with open(full_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for requirement ID at top of markdown
                first_line = content.split('\n')[0] if content else ""
                req_match = re.match(r'^#\s*\[(REQ-([A-Z]+)-(\d{3}))\]\s*(.*)$', first_line)
                if not req_match:
                    continue
                
                req_id = req_match.group(1)
                prefix = req_match.group(2)
                seq_num = int(req_match.group(3))
                title = req_match.group(4).strip()
                
                module_name = prefix_to_module.get(prefix, 'General Hardening Requirements')
                numeric_id = prefix_to_int.get(prefix, 9000) + seq_num
                
                # Extract priority
                priority_match = re.search(r'\*\s*\*\*Priority\*\*:\s*(\w+)', content, re.IGNORECASE)
                priority = priority_match.group(1).strip() if priority_match else "Medium"
                
                # Extract assessment type (automated vs manual)
                assessment_match = re.search(r'\*\s*\*\*(?:Assessment|Assessment Type|Verification Method)\*\*:\s*(\w+)', content, re.IGNORECASE)
                assessment_type = assessment_match.group(1).strip().lower() if assessment_match else "automated"
                
                # Extract rationale
                rationale = ""
                rationale_match = re.search(r'## Rationale\s*\n(.*?)(?=\n##|\n---|\n#)', content, re.DOTALL | re.IGNORECASE)
                if rationale_match:
                    rationale = rationale_match.group(1).strip()
                
                # Extract audit script URL relative target
                audit_script = None
                script_match = re.search(r'audit_scripts/([a-zA-Z0-9_-]+\.ps1)', content, re.IGNORECASE)
                if script_match:
                    script_name = script_match.group(1)
                    module_dir = os.path.dirname(rel_path).replace('\\', '/')
                    audit_script = f"{module_dir}/audit_scripts/{script_name}"
                
                # Extract implementation script URL relative target
                impl_script = None
                impl_match = re.search(r'implementation_scripts/([a-zA-Z0-9_-]+\.ps1)', content, re.IGNORECASE)
                if impl_match:
                    impl_name = impl_match.group(1)
                    module_dir = os.path.dirname(rel_path).replace('\\', '/')
                    impl_script = f"{module_dir}/implementation_scripts/{impl_name}"
                
                # Extract implementation steps text block
                impl_steps = ""
                impl_steps_match = re.search(r'## Implementation Steps\s*\n(.*?)(?=\n##\s|\Z)', content, re.DOTALL | re.IGNORECASE)
                if impl_steps_match:
                    impl_steps = impl_steps_match.group(1).strip()
                
                # Extract target scope
                scope = ""
                scope_match = re.search(r'## Target Scope\s*\n(.*?)(?=\n##|\n---)', content, re.DOTALL | re.IGNORECASE)
                if scope_match:
                    scope = scope_match.group(1).strip()
                
                # Initialize direct OVAL checks
                registry_checks = []
                service_checks = []
                user_rights = {}
                password_policy = {}
                lockout_policy = {}
                audit_policy = []
                
                # Helper helper to route service start key
                def add_reg_or_service_check(chk):
                    key = chk['key']
                    name = chk['name']
                    data = chk['data']
                    
                    if name.lower() == 'start' and re.search(r'^SYSTEM\\CurrentControlSet\\Services\\([^\\/]+)$', key, re.IGNORECASE):
                        svc_match = re.search(r'^SYSTEM\\CurrentControlSet\\Services\\([^\\/]+)$', key, re.IGNORECASE)
                        svc_name = svc_match.group(1)
                        start_type_map = {
                            '4': 'SERVICE_DISABLED',
                            '2': 'SERVICE_AUTO_START',
                            '3': 'SERVICE_DEMAND_START',
                            '1': 'SERVICE_SYSTEM_START',
                            '0': 'SERVICE_BOOT_START'
                        }
                        svc_start = start_type_map.get(data.strip(), 'SERVICE_DISABLED')
                        if not any(s['service_name'].lower() == svc_name.lower() for s in service_checks):
                            service_checks.append({
                                'service_name': svc_name,
                                'start_type': svc_start
                            })
                    else:
                        if not any(c['key'] == key and c['name'] == name and c['hive'] == chk['hive'] for c in registry_checks):
                            registry_checks.append(chk)
                
                # 1. First format (Key Path, Value Name, Value Type, Value Data list)
                bt = '`'
                pattern_key = r'(?:\*\*|\*|)?(?:Key Path|Registry Location)(?:\*\*|\*|)?:\s*' + bt + r'([^' + bt + r']+)' + bt
                pattern_name = r'(?:\*\*|\*|)?Value Name(?:\*\*|\*|)?:\s*' + bt + r'([^' + bt + r']+)' + bt
                pattern_type = r'(?:\*\*|\*|)?Value Type(?:\*\*|\*|)?:\s*' + bt + r'([^' + bt + r']+)' + bt
                pattern_data = r'(?:\*\*|\*|)?Value Data(?:\*\*|\*|)?:\s*' + bt + r'([^' + bt + r']+)' + bt
                pattern_hive = r'(?:\*\*|\*|)?Hive(?:\*\*|\*|)?:\s*' + bt + r'([^' + bt + r']+)' + bt
                
                key_paths = re.findall(pattern_key, content, re.IGNORECASE)
                val_names = re.findall(pattern_name, content, re.IGNORECASE)
                val_types = re.findall(pattern_type, content, re.IGNORECASE)
                val_datas = re.findall(pattern_data, content, re.IGNORECASE)
                hives = re.findall(pattern_hive, content, re.IGNORECASE)
                
                if key_paths and val_names:
                    for i in range(min(len(key_paths), len(val_names))):
                        vtype = val_types[i] if i < len(val_types) else "UNKNOWN"
                        vdata = val_datas[i] if i < len(val_datas) else "0"
                        hive_name = hives[i].strip() if i < len(hives) else None
                        
                        key_path = key_paths[i]
                        if hive_name and not any(key_path.upper().startswith(h) for h in ['HKLM', 'HKCU', 'HKU', 'HKCR', 'HKEY_']):
                            key_path = f"{hive_name}\\{key_path}"
                            
                        normalized = normalize_reg_check(key_path, val_names[i], vtype, vdata)
                        add_reg_or_service_check(normalized)
                        
                # 2. Line by line parser for other formats
                lines = content.split('\n')
                current_key = None
                in_code_block = False
                for line_idx, line in enumerate(lines):
                    line_strip = line.strip()
                    if line_strip.startswith('```'):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block:
                        # User Rights Assignments (PowerShell/INF style dictionary) can be inside code blocks
                        ura_match = re.search(r'"(Se[a-zA-Z0-9_]+)"\s*=\s*"([^"]*)"', line_strip)
                        if ura_match:
                            right_name = ura_match.group(1)
                            sids_str = ura_match.group(2)
                            sids = [s.strip().replace('*', '') for s in sids_str.split(',') if s.strip()]
                            user_rights[right_name] = sids
                        continue
                    if not line_strip:
                        continue
                        
                    if line_strip.startswith('#') or line_strip.startswith('---'):
                        current_key = None
                        continue
                    
                    # Parse registry
                    path_match = re.search(r'`?((?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\ \.-]+)`?', line_strip, re.IGNORECASE)
                    if not path_match:
                        path_match = re.search(r'`?((?:SYSTEM|SOFTWARE)\\CurrentControlSet\\[a-zA-Z0-9_\\ \.-]+)`?', line_strip, re.IGNORECASE)
                        if not path_match:
                            path_match = re.search(r'`?((?:SYSTEM|SOFTWARE)\\Policies\\[a-zA-Z0-9_\\ \.-]+)`?', line_strip, re.IGNORECASE)
                            
                    if path_match:
                        current_key = path_match.group(1).strip()
                        
                    if current_key:
                        val_match = re.search(r'`?([^`=\s]+)`?\s*=\s*(.+)', line_strip)
                        if val_match:
                            name = val_match.group(1).strip()
                            val_and_type = val_match.group(2).strip()
                            type_match = re.search(r'\s*\((REG_[A-Z0-9_]+|DWORD|SZ|BINARY|MULTI_SZ|UNKNOWN)[^)]*\)\s*$', val_and_type, re.IGNORECASE)
                            if type_match:
                                vtype = type_match.group(1)
                                val_part = val_and_type[:type_match.start()].strip()
                            else:
                                vtype = "UNKNOWN"
                                val_part = val_and_type
                            if val_part.startswith('`') and val_part.endswith('`'):
                                val_part = val_part[1:-1].strip()
                            if val_part.startswith('"') and val_part.endswith('"'):
                                val_part = val_part[1:-1].strip()
                            elif val_part.startswith("'") and val_part.endswith("'"):
                                val_part = val_part[1:-1].strip()
                            val = val_part
                            
                            is_valid_name = True
                            if ('\\' in name or '/' in name) and 'HardenedPaths' not in current_key:
                                is_valid_name = False
                            if is_valid_name and len(name) < 100 and name.lower() not in ['path', 'key path', 'value name', 'value type', 'value data', 'registry location']:
                                name_upper = name.upper()
                                if not name.startswith('(') and not name.endswith(')') and name_upper not in ['REG_DWORD', 'REG_SZ', 'REG_EXPAND_SZ', 'REG_MULTI_SZ', 'REG_BINARY', 'DWORD']:
                                    normalized = normalize_reg_check(current_key, name, vtype, val)
                                    add_reg_or_service_check(normalized)
                                
                    # User Rights Assignments (PowerShell/INF style dictionary)
                    ura_match = re.search(r'"(Se[a-zA-Z0-9_]+)"\s*=\s*"([^"]*)"', line_strip)
                    if ura_match:
                        right_name = ura_match.group(1)
                        sids_str = ura_match.group(2)
                        sids = [s.strip().replace('*', '') for s in sids_str.split(',') if s.strip()]
                        user_rights[right_name] = sids
                        
                    # Password & Lockout policies
                    inf_match = re.search(r'`?([a-zA-Z0-9_]+)`?\s*=\s*`?([0-9a-zA-Z_"]+)`?', line_strip)
                    if inf_match:
                        pname = inf_match.group(1).lower()
                        pval = inf_match.group(2).strip('"\'')
                        
                        if pname == 'minimumpasswordlength':
                            password_policy['min_passwd_len'] = int(pval)
                        elif pname == 'passwordcomplexity':
                            password_policy['password_complexity'] = pval == '1' or pval.lower() == 'true'
                        elif pname == 'passwordhistorysize':
                            password_policy['password_hist_len'] = int(pval)
                        elif pname == 'maxpasswordage':
                            days = int(pval)
                            password_policy['max_passwd_age'] = 4294967295 if days == 0 else days * 86400
                        elif pname == 'minpasswordage':
                            days = int(pval)
                            password_policy['min_passwd_age'] = days * 86400
                        elif pname == 'cleartextpassword':
                            password_policy['reversible_encryption'] = pval == '1' or pval.lower() == 'true'
                        elif pname == 'lockoutbadcount':
                            lockout_policy['lockout_threshold'] = int(pval)
                        elif pname == 'resetlockoutcount':
                            lockout_policy['lockout_observation_window'] = int(pval) * 60
                        elif pname == 'lockoutduration':
                            lockout_policy['lockout_duration'] = int(pval) * 60
                            
                    # Bullets / lists mapping (fallback)
                    list_match = re.search(r'\*\s*\*\*([^*]+)\*\*:\s*`?([0-9a-zA-Z\s_-]+)`?', line_strip, re.IGNORECASE)
                    if list_match:
                        lname = list_match.group(1).strip().lower()
                        lval = list_match.group(2).strip()
                        digits_match = re.match(r'\d+', lval)
                        digits = int(digits_match.group(0)) if digits_match else None
                        
                        if 'minimum password length' in lname:
                            if digits is not None: password_policy['min_passwd_len'] = digits
                        elif 'complexity requirements' in lname:
                            password_policy['password_complexity'] = 'enabled' in lval.lower() or 'true' in lval.lower()
                        elif 'password history' in lname:
                            if digits is not None: password_policy['password_hist_len'] = digits
                        elif 'maximum password age' in lname:
                            if digits is not None:
                                password_policy['max_passwd_age'] = 4294967295 if digits == 0 else digits * 86400
                        elif 'minimum password age' in lname:
                            if digits is not None: password_policy['min_passwd_age'] = digits * 86400
                        elif 'reversible encryption' in lname:
                            password_policy['reversible_encryption'] = 'enabled' in lval.lower() or 'true' in lval.lower()
                        elif 'lockout threshold' in lname:
                            if digits is not None: lockout_policy['lockout_threshold'] = digits
                        elif 'reset account lockout' in lname or 'lockout reset' in lname:
                            if digits is not None: lockout_policy['lockout_observation_window'] = digits * 60
                        elif 'lockout duration' in lname:
                            if digits is not None: lockout_policy['lockout_duration'] = digits * 60

                    # Advanced Audit Policies subcategories table
                    if '|' in line_strip and 'Audit ' in line_strip:
                        sub_match = re.search(r'`(Audit[^`]+)`', line_strip)
                        if sub_match:
                            sub_name = sub_match.group(1).strip()
                            parts = [p.strip() for p in line_strip.split('|')]
                            if len(parts) >= 4:
                                setting = parts[3]
                                key = sub_name.lower().replace('_', ' ').strip()
                                elem_name = subcat_mapping.get(key)
                                if elem_name:
                                    setting_val = "AUDIT_NONE"
                                    if "Success and Failure" in setting:
                                        setting_val = "AUDIT_SUCCESS_FAILURE"
                                    elif "Success" in setting:
                                        setting_val = "AUDIT_SUCCESS"
                                    elif "Failure" in setting:
                                        setting_val = "AUDIT_FAILURE"
                                    audit_policy.append({
                                        'subcat': elem_name,
                                        'setting': setting_val
                                    })
                                    
                    # Advanced Audit Policies list format (for audit-privileged-groups.md, etc.)
                    policy_match = re.search(r'\*\s*\*\*Policy\*\*:\s*`?(Audit[^`\n]+)`?', line_strip, re.IGNORECASE)
                    if policy_match:
                        p_name = policy_match.group(1).strip()
                        setting_val = "AUDIT_NONE"
                        for offset in range(1, 6):
                            if line_idx + offset < len(lines):
                                next_line = lines[line_idx + offset]
                                if 'setting' in next_line.lower():
                                    setting_match = re.search(r'Setting\*\*:\s*`?([^`\n]+)`?', next_line, re.IGNORECASE)
                                    if setting_match:
                                        s_text = setting_match.group(1).strip()
                                        if "Success and Failure" in s_text or ("Success" in s_text and "Failure" in s_text):
                                            setting_val = "AUDIT_SUCCESS_FAILURE"
                                        elif "Success" in s_text:
                                            setting_val = "AUDIT_SUCCESS"
                                        elif "Failure" in s_text:
                                            setting_val = "AUDIT_FAILURE"
                                        break
                        key = p_name.lower().replace('_', ' ').strip()
                        elem_name = subcat_mapping.get(key)
                        if elem_name:
                            audit_policy.append({
                                'subcat': elem_name,
                                'setting': setting_val
                            })
                                    
                # Inject user rights for Restrict Tier Logons requirement
                if 'implement-administrative-tiering-model.md' in rel_path.lower():
                    t0_sids = ['S-1-5-21-.*-512', 'S-1-5-21-.*-519', 'S-1-5-21-.*-518']
                    user_rights['SeDenyInteractiveLogonRight'] = t0_sids
                    user_rights['SeDenyNetworkLogonRight'] = t0_sids
                    user_rights['SeDenyRemoteInteractiveLogonRight'] = t0_sids
                    
                # Assign to profiles based on DSC lists
                profiles = []
                if audit_script:
                    audit_script_lower = audit_script.lower()
                    
                    if any(p.lower() == audit_script_lower for p in common_scripts):
                        profiles.extend(['DomainController', 'PAW', 'Endpoint'])
                    else:
                        if any(p.lower() == audit_script_lower for p in dc_scripts):
                            profiles.append('DomainController')
                        if any(p.lower() == audit_script_lower for p in paw_scripts):
                            profiles.append('PAW')
                        if any(p.lower() == audit_script_lower for p in endpoint_scripts):
                            profiles.append('Endpoint')
                
                # Fallback assignment based on requirement prefix if DSC mapping is absent
                if not profiles:
                    if prefix == 'ARCH' or prefix == 'DC':
                        profiles.append('DomainController')
                    elif prefix == 'PAW':
                        profiles.append('PAW')
                    elif prefix == 'END':
                        profiles.append('Endpoint')
                    else:
                        profiles.extend(['DomainController', 'PAW', 'Endpoint'])
                if not (registry_checks or service_checks or user_rights or password_policy or lockout_policy or audit_policy) and impl_script:
                    impl_path = os.path.join(repo_root, impl_script)
                    if os.path.exists(impl_path):
                        try:
                            with open(impl_path, 'r', encoding='utf-8') as f:
                                impl_content = f.read()
                            r_chks, s_chks = parse_ps1_for_registry_and_services(impl_content)
                            registry_checks.extend(r_chks)
                            service_checks.extend(s_chks)
                        except Exception as e:
                            print(f"Warning: Failed to parse implementation script {impl_path}: {e}")
                            
                requirements.append({
                    'id': req_id,
                    'prefix': prefix,
                    'numeric_id': numeric_id,
                    'title': title,
                    'priority': priority,
                    'rationale': rationale,
                    'audit_script': audit_script,
                    'impl_script': impl_script,
                    'impl_steps': impl_steps,
                    'registry_checks': registry_checks,
                    'service_checks': service_checks,
                    'user_rights': user_rights,
                    'password_policy': password_policy,
                    'lockout_policy': lockout_policy,
                    'audit_policy': audit_policy,
                    'scope': scope,
                    'markdown_file': rel_path.replace('\\', '/'),
                    'module_name': module_name,
                    'profiles': profiles,
                    'assessment_type': assessment_type
                })
                
    # Sort requirements by ID to ensure output stability
    requirements.sort(key=lambda x: x['id'])
    return requirements

def append_text(parent_el, text):
    if len(parent_el) == 0:
        if parent_el.text is None:
            parent_el.text = text
        else:
            parent_el.text += text
    else:
        last_child = parent_el[-1]
        if last_child.tail is None:
            last_child.tail = text
        else:
            last_child.tail += text

def parse_inline_formatting(parent_el, text, xhtml_ns):
    token_pattern = re.compile(r'(\*\*.*?\*\*|\*.*?\*|`.*?`|\[.*?\]\(.*?\))')
    parts = token_pattern.split(text)
    for part in parts:
        if not part:
            continue
        if part.startswith('**') and part.endswith('**'):
            strong_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}strong")
            strong_el.text = part[2:-2]
        elif part.startswith('*') and part.endswith('*'):
            em_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}em")
            em_el.text = part[1:-1]
        elif part.startswith('`') and part.endswith('`'):
            code_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}code")
            code_el.text = part[1:-1]
        elif part.startswith('[') and '](' in part and part.endswith(')'):
            link_match = re.match(r'^\[([^\]]+)\]\(([^)]+)\)$', part)
            if link_match:
                a_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}a", {'href': link_match.group(2)})
                a_el.text = link_match.group(1)
            else:
                append_text(parent_el, part)
        else:
            append_text(parent_el, part)

def split_paragraphs_respecting_code(md_text):
    paragraphs = []
    current_p_lines = []
    in_code_block = False
    
    for line in md_text.splitlines():
        line_strip = line.strip()
        if line_strip.startswith('```'):
            in_code_block = not in_code_block
            current_p_lines.append(line)
            continue
            
        if in_code_block:
            current_p_lines.append(line)
        else:
            if line_strip.startswith('#') or line_strip == '---':
                if current_p_lines:
                    paragraphs.append("\n".join(current_p_lines))
                    current_p_lines = []
                paragraphs.append(line)
                continue
                
            if not line_strip:
                if current_p_lines:
                    paragraphs.append("\n".join(current_p_lines))
                    current_p_lines = []
            else:
                current_p_lines.append(line)
                
    if current_p_lines:
        paragraphs.append("\n".join(current_p_lines))
        
    return paragraphs

def parse_markdown_to_xml(parent_el, md_text, xhtml_ns):
    paragraphs = split_paragraphs_respecting_code(md_text)
    for p_text in paragraphs:
        p_text = p_text.strip()
        if not p_text:
            continue
            
        lines = p_text.split('\n')
        
        # Check for code blocks
        if lines[0].strip().startswith('```'):
            code_lines = []
            for line in lines:
                line_strip = line.strip()
                if line_strip.startswith('```'):
                    continue
                code_lines.append(line)
            code_text = "\n".join(code_lines)
            pre_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}pre")
            code_el = ET.SubElement(pre_el, f"{{{xhtml_ns}}}code")
            code_el.text = code_text
            continue
            
        # Check for headings
        heading_match = re.match(r'^(#{1,6})\s+(.*)$', lines[0])
        if heading_match:
            level = len(heading_match.group(1))
            h_tag = f"{{{xhtml_ns}}}h{level}"
            h_el = ET.SubElement(parent_el, h_tag)
            h_text = " ".join(line.strip() for line in lines)
            h_text_clean = re.sub(r'^#{1,6}\s+', '', h_text)
            parse_inline_formatting(h_el, h_text_clean, xhtml_ns)
            continue
            
        # Check for horizontal rules
        if lines[0].strip() == '---':
            ET.SubElement(parent_el, f"{{{xhtml_ns}}}hr")
            continue
            
        is_list = False
        is_ordered = False
        
        if re.match(r'^\s*[\*\-]\s+', lines[0]):
            is_list = True
        elif re.match(r'^\s*\d+\.\s+', lines[0]):
            is_list = True
            is_ordered = True
            
        if is_list:
            list_tag = f"{{{xhtml_ns}}}ol" if is_ordered else f"{{{xhtml_ns}}}ul"
            list_el = ET.SubElement(parent_el, list_tag)
            for line in lines:
                line_strip = line.strip()
                if is_ordered:
                    item_text = re.sub(r'^\d+\.\s+', '', line_strip)
                else:
                    item_text = re.sub(r'^[\*\-]\s+', '', line_strip)
                li_el = ET.SubElement(list_el, f"{{{xhtml_ns}}}li")
                parse_inline_formatting(li_el, item_text, xhtml_ns)
        else:
            p_el = ET.SubElement(parent_el, f"{{{xhtml_ns}}}p")
            p_text_inline = " ".join(line.strip() for line in lines)
            parse_inline_formatting(p_el, p_text_inline, xhtml_ns)

def generate_xccdf(requirements, output_path, repo_root):
    """
    Generates a valid XCCDF 1.2 Benchmark XML.
    """
    XCCDF_NS = 'http://checklists.nist.gov/xccdf/1.2'
    DC_NS = 'http://purl.org/dc/elements/1.1/'
    XHTML_NS = 'http://www.w3.org/1999/xhtml'
    
    ET.register_namespace('', XCCDF_NS)
    ET.register_namespace('dc', DC_NS)
    ET.register_namespace('xhtml', XHTML_NS)
    
    def x_tag(name):
        return f"{{{XCCDF_NS}}}{name}"
        
    root = ET.Element(x_tag('Benchmark'), {
        'id': 'xccdf_org.adhardening.benchmarks_benchmark_ad-hardening',
        'resolved': 'false',
        'xml:lang': 'en'
    })
    
    status = ET.SubElement(root, x_tag('status'), {'date': datetime.now().strftime('%Y-%m-%d')})
    status.text = 'accepted'
    
    title = ET.SubElement(root, x_tag('title'))
    title.text = 'Active Directory Hardening Guidebook Benchmark'
    
    desc = ET.SubElement(root, x_tag('description'))
    desc.text = 'Automated compliance checklist profiles and rules parsed directly from the Active Directory Hardening Guidebook.'
    
    version = ET.SubElement(root, x_tag('version'))
    version.text = '1.0'
    
    metadata = ET.SubElement(root, x_tag('metadata'))
    dc_publisher = ET.SubElement(metadata, f"{{{DC_NS}}}publisher")
    dc_publisher.text = 'Antigravity Hardening Project'
    dc_creator = ET.SubElement(metadata, f"{{{DC_NS}}}creator")
    dc_creator.text = 'Antigravity'
    dc_date = ET.SubElement(metadata, f"{{{DC_NS}}}date")
    dc_date.text = datetime.now().strftime('%Y-%m-%d')
    
    # Define Profiles
    profiles_meta = [
        ('DomainController', 'Domain Controller Hardening Profile', 'Applies all Tier 0 infrastructure and Domain Controller security checks.'),
        ('PAW', 'Privileged Access Workstations (PAW) Hardening Profile', 'Applies security restrictions specifically targeting PAWs.'),
        ('Endpoint', 'Endpoint Hardening Profile', 'Applies security baselines for general client workstations and endpoints.')
    ]
    
    for prof_id, prof_title, prof_desc in profiles_meta:
        prof_el = ET.SubElement(root, x_tag('Profile'), {
            'id': f'xccdf_org.adhardening.benchmarks_profile_{prof_id}'
        })
        p_title = ET.SubElement(prof_el, x_tag('title'))
        p_title.text = prof_title
        p_desc = ET.SubElement(prof_el, x_tag('description'))
        p_desc.text = prof_desc
        
        # Select rules for this profile
        for req in requirements:
            if prof_id in req['profiles']:
                ET.SubElement(prof_el, x_tag('select'), {
                    'idref': f'xccdf_org.adhardening.benchmarks_rule_{req["id"]}',
                    'selected': 'true'
                })
                
    # Group rules by Module
    modules = {}
    for req in requirements:
        mod = req['module_name']
        if mod not in modules:
            modules[mod] = []
        modules[mod].append(req)
        
    for mod_name, reqs in sorted(modules.items()):
        group_id = 'xccdf_org.adhardening.benchmarks_group_' + re.sub(r'[^a-zA-Z0-9]', '_', mod_name)
        group_el = ET.SubElement(root, x_tag('Group'), {'id': group_id})
        g_title = ET.SubElement(group_el, x_tag('title'))
        g_title.text = mod_name
        
        for req in reqs:
            severity = req['priority'].lower()
            if severity not in ['high', 'medium', 'low']:
                severity = 'medium'
                
            rule_el = ET.SubElement(group_el, x_tag('Rule'), {
                'id': f'xccdf_org.adhardening.benchmarks_rule_{req["id"]}',
                'severity': severity,
                'weight': '10.0',
                'selected': 'false'
            })
            
            r_title = ET.SubElement(rule_el, x_tag('title'))
            r_title.text = f"[{req['id']}] {req['title']}"
            
            r_desc = ET.SubElement(rule_el, x_tag('description'))
            if req['scope']:
                scope_header_p = ET.SubElement(r_desc, f"{{{XHTML_NS}}}p")
                scope_strong = ET.SubElement(scope_header_p, f"{{{XHTML_NS}}}strong")
                scope_strong.text = "Target Scope:"
                parse_markdown_to_xml(r_desc, req['scope'], XHTML_NS)
            else:
                scope_p = ET.SubElement(r_desc, f"{{{XHTML_NS}}}p")
                scope_strong = ET.SubElement(scope_p, f"{{{XHTML_NS}}}strong")
                scope_strong.text = "Target Scope: Not Specified"
                
            path_p = ET.SubElement(r_desc, f"{{{XHTML_NS}}}p")
            path_strong = ET.SubElement(path_p, f"{{{XHTML_NS}}}strong")
            path_strong.text = "File Path: "
            path_code = ET.SubElement(path_p, f"{{{XHTML_NS}}}code")
            path_code.text = req['markdown_file']
            
            if req['rationale']:
                r_rat = ET.SubElement(rule_el, x_tag('rationale'))
                parse_markdown_to_xml(r_rat, req['rationale'], XHTML_NS)
                
            if req['impl_steps']:
                r_fixtext = ET.SubElement(rule_el, x_tag('fixtext'))
                parse_markdown_to_xml(r_fixtext, req['impl_steps'], XHTML_NS)
                
            # If the requirement has an implementation script, embed it as a fix element
            if req['impl_script']:
                impl_path = os.path.join(repo_root, req['impl_script'])
                if os.path.exists(impl_path):
                    try:
                        with open(impl_path, 'r', encoding='utf-8') as sf:
                            script_content = sf.read().strip()
                        if script_content:
                            fix_el = ET.SubElement(rule_el, x_tag('fix'), {
                                'system': 'urn:xccdf:fix:script:powershell'
                            })
                            fix_el.text = script_content
                    except Exception as e:
                        print(f"Warning: Failed to read implementation script {impl_path}: {e}")
                
            # If the requirement has an automated audit script, link appropriate check
            if req['audit_script']:
                if req.get('assessment_type') == 'manual':
                    chk_el = ET.SubElement(rule_el, x_tag('check'), {
                        'system': 'http://checklists.nist.gov/xccdf/check/manual'
                    })
                    content_el = ET.SubElement(chk_el, x_tag('check-content'))
                    content_el.text = "Perform manual verification steps as documented in the guidebook."
                else:
                    chk_el = ET.SubElement(rule_el, x_tag('check'), {
                        'system': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
                    })
                    ET.SubElement(chk_el, x_tag('check-content-ref'), {
                        'href': 'ad-hardening-oval.xml',
                        'name': f"oval:org.adhardening:def:{req['numeric_id']}"
                    })
                
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    print(f"Generated XCCDF Benchmark at: {output_path}")

def generate_oval(requirements, output_path):
    """
    Generates a valid OVAL 5.11 Definitions XML.
    """
    OVAL_NS = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    OVAL_COMMON_NS = 'http://oval.mitre.org/XMLSchema/oval-common-5'
    OVAL_IND_NS = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
    OVAL_WIN_NS = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows'
    XSI_NS = 'http://www.w3.org/2001/XMLSchema-instance'
    
    ET.register_namespace('', OVAL_NS)
    ET.register_namespace('oval', OVAL_COMMON_NS)
    ET.register_namespace('independent', OVAL_IND_NS)
    ET.register_namespace('windows', OVAL_WIN_NS)
    ET.register_namespace('xsi', XSI_NS)
    
    def o_tag(name):
        return f"{{{OVAL_NS}}}{name}"
    def c_tag(name):
        return f"{{{OVAL_COMMON_NS}}}{name}"
    def i_tag(name):
        return f"{{{OVAL_IND_NS}}}{name}"
    def w_tag(name):
        return f"{{{OVAL_WIN_NS}}}{name}"
        
    root = ET.Element(o_tag('oval_definitions'), {
        f"{{{XSI_NS}}}schemaLocation": (
            'http://oval.mitre.org/XMLSchema/oval-definitions-5 oval-definitions-schema.xsd '
            'http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd '
            'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent independent-definitions-schema.xsd '
            'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows windows-definitions-schema.xsd'
        )
    })
    
    generator = ET.SubElement(root, o_tag('generator'))
    schema_ver = ET.SubElement(generator, c_tag('schema_version'))
    schema_ver.text = '5.11.2'
    timestamp = ET.SubElement(generator, c_tag('timestamp'))
    timestamp.text = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    defs_el = ET.SubElement(root, o_tag('definitions'))
    tests_el = ET.SubElement(root, o_tag('tests'))
    objs_el = ET.SubElement(root, o_tag('objects'))
    states_el = ET.SubElement(root, o_tag('states'))
    
    # Check if we need to insert the global 'any_sid' state for empty user rights (renamed to 9999 to satisfy ID pattern)
    has_empty_user_rights = any(
        req['user_rights'] and any(len(sids) == 0 for sids in req['user_rights'].values())
        for req in requirements
    )
    if has_empty_user_rights:
        ste_el = ET.SubElement(states_el, w_tag('userright_state'), {
            'id': 'oval:org.adhardening:ste:9999',
            'version': '1'
        })
        val_el = ET.SubElement(ste_el, w_tag('trustee_sid'), {
            'operation': 'pattern match'
        })
        val_el.text = '.*'
        
    # Filter requirements that can be evaluated (either has registry checks, services, user rights, etc. or has audit script) and are not manual
    oval_reqs = [
        r for r in requirements
        if (r['registry_checks'] or r['service_checks'] or r['user_rights'] or r['password_policy'] or r['lockout_policy'] or r['audit_policy'] or r['audit_script'])
        and r.get('assessment_type') != 'manual'
    ]
    
    for req in oval_reqs:
        # 1. Definition
        def_id = f"oval:org.adhardening:def:{req['numeric_id']}"
        def_el = ET.SubElement(defs_el, o_tag('definition'), {
            'id': def_id,
            'version': '1',
            'class': 'compliance'
        })
        
        meta = ET.SubElement(def_el, o_tag('metadata'))
        m_title = ET.SubElement(meta, o_tag('title'))
        m_title.text = f"[{req['id']}] {req['title']}"
        
        affected = ET.SubElement(meta, o_tag('affected'), {'family': 'windows'})
        platforms = [
            'Microsoft Windows Server 2016',
            'Microsoft Windows Server 2019',
            'Microsoft Windows Server 2022',
            'Microsoft Windows 10',
            'Microsoft Windows 11'
        ]
        for plat in platforms:
            p_el = ET.SubElement(affected, o_tag('platform'))
            p_el.text = plat
            
        m_desc = ET.SubElement(meta, o_tag('description'))
        m_desc.text = req['rationale'] or f"Compliance check for {req['title']}."
        
        criteria = ET.SubElement(def_el, o_tag('criteria'), {'operator': 'AND'})
        
        # Keep track of whether we generated any native checks
        has_native = False
        
        # Native Registry Checks
        if req['registry_checks']:
            has_native = True
            for idx, chk in enumerate(req['registry_checks'], start=1):
                sub_id = req['numeric_id'] * 1000 + idx
                comment = f"Check Registry Key {chk['key']} Value {chk['name']}"
                is_inv_logging = (chk['name'] == 'EnableScriptBlockInvocationLogging')
                
                if is_inv_logging:
                    or_criteria = ET.SubElement(criteria, o_tag('criteria'), {'operator': 'OR'})
                    ET.SubElement(or_criteria, o_tag('criterion'), {
                        'comment': comment + " is 0",
                        'test_ref': f"oval:org.adhardening:tst:{sub_id}"
                    })
                    sub_id_missing = sub_id + 500
                    ET.SubElement(or_criteria, o_tag('criterion'), {
                        'comment': comment + " is missing",
                        'test_ref': f"oval:org.adhardening:tst:{sub_id_missing}"
                    })
                else:
                    ET.SubElement(criteria, o_tag('criterion'), {
                        'comment': comment,
                        'test_ref': f"oval:org.adhardening:tst:{sub_id}"
                    })
                
                # registry_test
                test_attrs = {
                    'id': f"oval:org.adhardening:tst:{sub_id}",
                    'version': '1',
                    'comment': comment + " is 0" if is_inv_logging else comment,
                    'check': 'all'
                }
                if chk.get('existence') == 'none_exist':
                    test_attrs['check_existence'] = 'none_exist'
                    
                test_el = ET.SubElement(tests_el, w_tag('registry_test'), test_attrs)
                ET.SubElement(test_el, w_tag('object'), {
                    'object_ref': f"oval:org.adhardening:obj:{sub_id}"
                })
                if chk.get('existence') != 'none_exist':
                    ET.SubElement(test_el, w_tag('state'), {
                        'state_ref': f"oval:org.adhardening:ste:{sub_id}"
                    })
                
                if is_inv_logging:
                    sub_id_missing = sub_id + 500
                    test_attrs_missing = {
                        'id': f"oval:org.adhardening:tst:{sub_id_missing}",
                        'version': '1',
                        'comment': comment + " is missing",
                        'check': 'all',
                        'check_existence': 'none_exist'
                    }
                    test_el_missing = ET.SubElement(tests_el, w_tag('registry_test'), test_attrs_missing)
                    ET.SubElement(test_el_missing, w_tag('object'), {
                        'object_ref': f"oval:org.adhardening:obj:{sub_id}"
                    })
                
                # registry_object
                obj_el = ET.SubElement(objs_el, w_tag('registry_object'), {
                    'id': f"oval:org.adhardening:obj:{sub_id}",
                    'version': '1'
                })
                # Add 64-bit registry view behavior to prevent Wow6432Node redirection failures
                ET.SubElement(obj_el, w_tag('behaviors'), {
                    'windows_view': '64_bit'
                })
                hive_el = ET.SubElement(obj_el, w_tag('hive'))
                hive_el.text = chk['hive']
                key_el = ET.SubElement(obj_el, w_tag('key'))
                key_val = chk['key']
                if '.*' in key_val or '<' in key_val or '?' in key_val:
                    key_val_regex = key_val.replace('<InterfaceKey>', '.*').replace('<', '.*').replace('>', '.*')
                    key_el.set('operation', 'pattern match')
                    key_el.text = key_val_regex
                else:
                    key_el.text = key_val
                name_el = ET.SubElement(obj_el, w_tag('name'))
                name_el.text = chk['name']
                
                # registry_state
                if chk.get('existence') != 'none_exist':
                    state_el = ET.SubElement(states_el, w_tag('registry_state'), {
                        'id': f"oval:org.adhardening:ste:{sub_id}",
                        'version': '1'
                    })
                    type_el = ET.SubElement(state_el, w_tag('type'))
                    type_el.text = chk['type']
                    
                    datatype = 'int' if chk['type'] == 'reg_dword' else 'string'
                    val_attrs = {'datatype': datatype}
                    if chk.get('operation') and chk['operation'] != 'equals':
                        val_attrs['operation'] = chk['operation']
                    val_el = ET.SubElement(state_el, w_tag('value'), val_attrs)
                    val_el.text = chk['data']
                
        # Native Service Checks
        if req['service_checks']:
            has_native = True
            for idx, chk in enumerate(req['service_checks'], start=50):
                sub_id = req['numeric_id'] * 1000 + 100 + idx
                comment = f"Check Startup Configuration for Service {chk['service_name']}"
                
                # Map service start type to registry Start value
                start_map = {
                    'SERVICE_BOOT_START': '0',
                    'SERVICE_BOOT': '0',
                    'SERVICE_SYSTEM_START': '1',
                    'SERVICE_SYSTEM': '1',
                    'SERVICE_AUTO_START': '2',
                    'SERVICE_AUTO': '2',
                    'SERVICE_DEMAND_START': '3',
                    'SERVICE_DEMAND': '3',
                    'SERVICE_DISABLED': '4',
                    'DISABLED': '4'
                }
                data_val = start_map.get(chk['start_type'].upper(), '4')
                
                ET.SubElement(criteria, o_tag('criterion'), {
                    'comment': comment,
                    'test_ref': f"oval:org.adhardening:tst:{sub_id}"
                })
                
                # registry_test
                test_el = ET.SubElement(tests_el, w_tag('registry_test'), {
                    'id': f"oval:org.adhardening:tst:{sub_id}",
                    'version': '1',
                    'comment': comment,
                    'check': 'all'
                })
                ET.SubElement(test_el, w_tag('object'), {
                    'object_ref': f"oval:org.adhardening:obj:{sub_id}"
                })
                ET.SubElement(test_el, w_tag('state'), {
                    'state_ref': f"oval:org.adhardening:ste:{sub_id}"
                })
                
                # registry_object
                obj_el = ET.SubElement(objs_el, w_tag('registry_object'), {
                    'id': f"oval:org.adhardening:obj:{sub_id}",
                    'version': '1'
                })
                # Add 64-bit registry view behavior to prevent Wow6432Node redirection failures
                ET.SubElement(obj_el, w_tag('behaviors'), {
                    'windows_view': '64_bit'
                })
                hive_el = ET.SubElement(obj_el, w_tag('hive'))
                hive_el.text = 'HKEY_LOCAL_MACHINE'
                
                key_el = ET.SubElement(obj_el, w_tag('key'))
                key_el.text = f"SYSTEM\\CurrentControlSet\\Services\\{chk['service_name']}"
                
                name_el = ET.SubElement(obj_el, w_tag('name'))
                name_el.text = 'Start'
                
                # registry_state
                state_el = ET.SubElement(states_el, w_tag('registry_state'), {
                    'id': f"oval:org.adhardening:ste:{sub_id}",
                    'version': '1'
                })
                type_el = ET.SubElement(state_el, w_tag('type'))
                type_el.text = 'reg_dword'
                
                val_el = ET.SubElement(state_el, w_tag('value'), {
                    'datatype': 'int'
                })
                val_el.text = data_val
                
        # Native User Rights Checks
        if req['user_rights']:
            has_native = True
            for idx, (right_name, sids) in enumerate(req['user_rights'].items(), start=10):
                sub_id = req['numeric_id'] * 1000 + 200 + idx
                comment = f"Check User Right Assignment {right_name}"
                
                ET.SubElement(criteria, o_tag('criterion'), {
                    'comment': comment,
                    'test_ref': f"oval:org.adhardening:tst:{sub_id}"
                })
                
                # userright_test
                check_type = 'none satisfy' if len(sids) == 0 else 'all'
                test_el = ET.SubElement(tests_el, w_tag('userright_test'), {
                    'id': f"oval:org.adhardening:tst:{sub_id}",
                    'version': '1',
                    'comment': comment,
                    'check': check_type
                })
                ET.SubElement(test_el, w_tag('object'), {
                    'object_ref': f"oval:org.adhardening:obj:{sub_id}"
                })
                
                # userright_object
                obj_el = ET.SubElement(objs_el, w_tag('userright_object'), {
                    'id': f"oval:org.adhardening:obj:{sub_id}",
                    'version': '1'
                })
                right_el = ET.SubElement(obj_el, w_tag('userright'))
                right_el.text = userright_mapping.get(right_name, right_name)
                
                if len(sids) == 0:
                    ET.SubElement(test_el, w_tag('state'), {
                        'state_ref': 'oval:org.adhardening:ste:9999'
                    })
                else:
                    ET.SubElement(test_el, w_tag('state'), {
                        'state_ref': f"oval:org.adhardening:ste:{sub_id}"
                    })
                    
                    # userright_state
                    state_el = ET.SubElement(states_el, w_tag('userright_state'), {
                        'id': f"oval:org.adhardening:ste:{sub_id}",
                        'version': '1'
                    })
                    sid_el = ET.SubElement(state_el, w_tag('trustee_sid'), {
                        'operation': 'pattern match'
                    })
                    # Compile regex pattern: ^(SID1|SID2)$
                    sid_el.text = "^(" + "|".join(sids) + ")$"
                    
        # Native Password Policy Check
        if req['password_policy']:
            has_native = True
            sub_id = req['numeric_id'] * 1000 + 900
            comment = f"Check local Password Policy settings"
            
            ET.SubElement(criteria, o_tag('criterion'), {
                'comment': comment,
                'test_ref': f"oval:org.adhardening:tst:{sub_id}"
            })
            
            # passwordpolicy_test
            test_el = ET.SubElement(tests_el, w_tag('passwordpolicy_test'), {
                'id': f"oval:org.adhardening:tst:{sub_id}",
                'version': '1',
                'comment': comment,
                'check': 'all'
            })
            ET.SubElement(test_el, w_tag('object'), {
                'object_ref': f"oval:org.adhardening:obj:{sub_id}"
            })
            ET.SubElement(test_el, w_tag('state'), {
                'state_ref': f"oval:org.adhardening:ste:{sub_id}"
            })
            
            # passwordpolicy_object
            ET.SubElement(objs_el, w_tag('passwordpolicy_object'), {
                'id': f"oval:org.adhardening:obj:{sub_id}",
                'version': '1'
            })
            
            # passwordpolicy_state
            state_el = ET.SubElement(states_el, w_tag('passwordpolicy_state'), {
                'id': f"oval:org.adhardening:ste:{sub_id}",
                'version': '1'
            })
            
            p = req['password_policy']
            if 'max_passwd_age' in p:
                age_el = ET.SubElement(state_el, w_tag('max_passwd_age'), {'datatype': 'int'})
                age_el.text = str(p['max_passwd_age'])
            if 'min_passwd_age' in p:
                age_el = ET.SubElement(state_el, w_tag('min_passwd_age'), {'datatype': 'int'})
                age_el.text = str(p['min_passwd_age'])
            if 'min_passwd_len' in p:
                len_el = ET.SubElement(state_el, w_tag('min_passwd_len'), {'datatype': 'int'})
                len_el.text = str(p['min_passwd_len'])
            if 'password_hist_len' in p:
                hist_el = ET.SubElement(state_el, w_tag('password_hist_len'), {'datatype': 'int'})
                hist_el.text = str(p['password_hist_len'])
            if 'password_complexity' in p:
                comp_el = ET.SubElement(state_el, w_tag('password_complexity'), {'datatype': 'boolean'})
                comp_el.text = 'true' if p['password_complexity'] else 'false'
            if 'reversible_encryption' in p:
                rev_el = ET.SubElement(state_el, w_tag('reversible_encryption'), {'datatype': 'boolean'})
                rev_el.text = 'true' if p['reversible_encryption'] else 'false'
                
        # Native Lockout Policy Check
        if req['lockout_policy']:
            has_native = True
            sub_id = req['numeric_id'] * 1000 + 910
            comment = f"Check local Account Lockout Policy settings"
            
            ET.SubElement(criteria, o_tag('criterion'), {
                'comment': comment,
                'test_ref': f"oval:org.adhardening:tst:{sub_id}"
            })
            
            # lockoutpolicy_test
            test_el = ET.SubElement(tests_el, w_tag('lockoutpolicy_test'), {
                'id': f"oval:org.adhardening:tst:{sub_id}",
                'version': '1',
                'comment': comment,
                'check': 'all'
            })
            ET.SubElement(test_el, w_tag('object'), {
                'object_ref': f"oval:org.adhardening:obj:{sub_id}"
            })
            ET.SubElement(test_el, w_tag('state'), {
                'state_ref': f"oval:org.adhardening:ste:{sub_id}"
            })
            
            # lockoutpolicy_object
            ET.SubElement(objs_el, w_tag('lockoutpolicy_object'), {
                'id': f"oval:org.adhardening:obj:{sub_id}",
                'version': '1'
            })
            
            # lockoutpolicy_state
            state_el = ET.SubElement(states_el, w_tag('lockoutpolicy_state'), {
                'id': f"oval:org.adhardening:ste:{sub_id}",
                'version': '1'
            })
            
            l = req['lockout_policy']
            if 'lockout_duration' in l:
                dur_el = ET.SubElement(state_el, w_tag('lockout_duration'), {'datatype': 'int'})
                dur_el.text = str(l['lockout_duration'])
            if 'lockout_observation_window' in l:
                obs_el = ET.SubElement(state_el, w_tag('lockout_observation_window'), {'datatype': 'int'})
                obs_el.text = str(l['lockout_observation_window'])
            if 'lockout_threshold' in l:
                thr_el = ET.SubElement(state_el, w_tag('lockout_threshold'), {'datatype': 'int'})
                thr_el.text = str(l['lockout_threshold'])
                
        # Native Advanced Audit Policy Check
        # Native Advanced Audit Policy Check
        # (Omitted due to schema version incompatibility in common OVAL 5.11.2 validators like OpenSCAP)
        # if req['audit_policy']:
        #     has_native = True
        #     sub_id = req['numeric_id'] * 1000 + 920
        #     comment = f"Check Advanced Audit Policy configurations"
        #     
        #     ET.SubElement(criteria, o_tag('criterion'), {
        #         'comment': comment,
        #         'test_ref': f"oval:org.adhardening:tst:{sub_id}"
        #     })
        #     
        #     # auditeventpolicysubcategories_test
        #     test_el = ET.SubElement(tests_el, w_tag('auditeventpolicysubcategories_test'), {
        #         'id': f"oval:org.adhardening:tst:{sub_id}",
        #         'version': '1',
        #         'comment': comment,
        #         'check': 'all'
        #     })
        #     ET.SubElement(test_el, w_tag('object'), {
        #         'object_ref': f"oval:org.adhardening:obj:{sub_id}"
        #     })
        #     ET.SubElement(test_el, w_tag('state'), {
        #         'state_ref': f"oval:org.adhardening:ste:{sub_id}"
        #     })
        #     
        #     # auditeventpolicysubcategories_object
        #     ET.SubElement(objs_el, w_tag('auditeventpolicysubcategories_object'), {
        #         'id': f"oval:org.adhardening:obj:{sub_id}",
        #         'version': '1'
        #     })
        #     
        #     # auditeventpolicysubcategories_state
        #     state_el = ET.SubElement(states_el, w_tag('auditeventpolicysubcategories_state'), {
        #         'id': f"oval:org.adhardening:ste:{sub_id}",
        #         'version': '1'
        #     })
        #     
        #     for item in req['audit_policy']:
        #         item_el = ET.SubElement(state_el, w_tag(item['subcat']))
        #         item_el.text = item['setting']
                
        # Fallback to Placeholder Registry Test if no native checks were generated
        if not has_native and req['audit_script']:
            comment = f"Placeholder check for {req['id']} (requires PowerShell audit script)"
            ET.SubElement(criteria, o_tag('criterion'), {
                'comment': comment,
                'test_ref': f"oval:org.adhardening:tst:{req['numeric_id']}"
            })
            
            # registry_test
            test_el = ET.SubElement(tests_el, w_tag('registry_test'), {
                'id': f"oval:org.adhardening:tst:{req['numeric_id']}",
                'version': '1',
                'comment': comment,
                'check': 'all'
            })
            ET.SubElement(test_el, w_tag('object'), {
                'object_ref': f"oval:org.adhardening:obj:{req['numeric_id']}"
            })
            ET.SubElement(test_el, w_tag('state'), {
                'state_ref': f"oval:org.adhardening:ste:{req['numeric_id']}"
            })
            
            # registry_object
            obj_el = ET.SubElement(objs_el, w_tag('registry_object'), {
                'id': f"oval:org.adhardening:obj:{req['numeric_id']}",
                'version': '1'
            })
            # Add 64-bit registry view behavior to prevent Wow6432Node redirection failures
            ET.SubElement(obj_el, w_tag('behaviors'), {
                'windows_view': '64_bit'
            })
            hive_el = ET.SubElement(obj_el, w_tag('hive'))
            hive_el.text = 'HKEY_LOCAL_MACHINE'
            key_el = ET.SubElement(obj_el, w_tag('key'))
            key_el.text = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
            name_el = ET.SubElement(obj_el, w_tag('name'))
            name_el.text = 'SystemRoot'
            
            # registry_state
            state_el = ET.SubElement(states_el, w_tag('registry_state'), {
                'id': f"oval:org.adhardening:ste:{req['numeric_id']}",
                'version': '1'
            })
            type_el = ET.SubElement(state_el, w_tag('type'))
            type_el.text = 'reg_sz'
            val_el = ET.SubElement(state_el, w_tag('value'), {
                'datatype': 'string',
                'operation': 'pattern match'
            })
            val_el.text = '.*'
        
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    print(f"Generated OVAL Definitions at: {output_path}")

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    dsc_path = os.path.join(repo_root, 'audit', 'dsc', 'ADHardeningAudit.ps1')
    scap_dir = os.path.join(repo_root, 'audit', 'scap')
    
    if not os.path.exists(scap_dir):
        os.makedirs(scap_dir)
        
    xccdf_output = os.path.join(scap_dir, 'ad-hardening-xccdf.xml')
    oval_output = os.path.join(scap_dir, 'ad-hardening-oval.xml')
    
    print("Parsing DSC profile configuration...")
    common_scripts, dc_scripts, paw_scripts, endpoint_scripts = parse_dsc_profiles(dsc_path)
    print(f"DSC parsed: {len(common_scripts)} common scripts, {len(dc_scripts)} DC scripts, {len(paw_scripts)} PAW scripts, {len(endpoint_scripts)} Endpoint scripts.")
    
    print("\nScanning markdown requirements...")
    requirements = scan_markdown_requirements(repo_root, common_scripts, dc_scripts, paw_scripts, endpoint_scripts)
    print(f"Found {len(requirements)} requirement records.")
    
    print("\nGenerating compliance files...")
    generate_xccdf(requirements, xccdf_output, repo_root)
    generate_oval(requirements, oval_output)
    print("\nCompliance metadata generation complete!")

if __name__ == '__main__':
    main()
