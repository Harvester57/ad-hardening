import os
import sys
import xml.etree.ElementTree as ET

def load_xsd_elements(xsd_paths):
    elements = set()
    for xsd_path in xsd_paths:
        if not os.path.exists(xsd_path):
            continue
        try:
            tree = ET.parse(xsd_path)
            root = tree.getroot()
            for el in root.findall('.//{http://www.w3.org/2001/XMLSchema}element'):
                name = el.attrib.get('name')
                if name:
                    elements.add(name)
        except Exception as e:
            print(f"Warning: Failed to parse XSD {xsd_path}: {e}")
    return elements

def validate_xccdf(xccdf_path, oval_definition_ids):
    print(f"Validating XCCDF: {xccdf_path}")
    if not os.path.exists(xccdf_path):
        print(f"Error: XCCDF file not found at {xccdf_path}")
        return False
        
    try:
        tree = ET.parse(xccdf_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error: XCCDF is not well-formed XML: {e}")
        return False
        
    xccdf_ns = 'http://checklists.nist.gov/xccdf/1.2'
    if root.tag != f"{{{xccdf_ns}}}Benchmark":
        print(f"Error: XCCDF root tag must be {{{xccdf_ns}}}Benchmark, found: {root.tag}")
        return False
        
    errors = 0
    rules = root.findall(f'.//{{{xccdf_ns}}}Rule')
    print(f"  Found {len(rules)} XCCDF Rules.")
    
    for rule in rules:
        rule_id = rule.attrib.get('id', 'unknown')
        checks = rule.findall(f'{{{xccdf_ns}}}check')
        if not checks:
            print(f"Error: Rule {rule_id} has no check defined.")
            errors += 1
            continue
            
        for check in checks:
            check_system = check.attrib.get('system', '')
            if 'oval' not in check_system.lower():
                continue
            check_content = check.find(f'{{{xccdf_ns}}}check-content-ref')
            if check_content is None:
                print(f"Error: Rule {rule_id} has check but no check-content-ref.")
                errors += 1
                continue
                
            name = check_content.attrib.get('name')
            if not name:
                print(f"Error: Rule {rule_id} check-content-ref has no name attribute.")
                errors += 1
                continue
                
            if name not in oval_definition_ids:
                print(f"Error: Rule {rule_id} references missing OVAL Definition: {name}")
                errors += 1
                
    return errors == 0

def validate_oval(oval_path, xsd_elements):
    print(f"Validating OVAL: {oval_path}")
    if not os.path.exists(oval_path):
        print(f"Error: OVAL file not found at {oval_path}")
        return False, set()
        
    try:
        tree = ET.parse(oval_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Error: OVAL is not well-formed XML: {e}")
        return False, set()
        
    oval_ns = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    win_ns = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows'
    ind_ns = 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
    
    if root.tag != f"{{{oval_ns}}}oval_definitions":
        print(f"Error: OVAL root tag must be {{{oval_ns}}}oval_definitions, found: {root.tag}")
        return False, set()
        
    # Extract IDs
    definitions = root.findall(f'{{{oval_ns}}}definitions/{{{oval_ns}}}definition')
    tests = root.findall(f'{{{oval_ns}}}tests/*')
    objects = root.findall(f'{{{oval_ns}}}objects/*')
    states = root.findall(f'{{{oval_ns}}}states/*')
    
    definition_ids = {d.attrib['id'] for d in definitions}
    test_ids = {t.attrib['id'] for t in tests}
    object_ids = {o.attrib['id'] for o in objects}
    state_ids = {s.attrib['id'] for s in states}
    
    print(f"  Found {len(definitions)} definitions, {len(tests)} tests, {len(objects)} objects, {len(states)} states.")
    
    errors = 0
    
    # 1. Verify Definition -> Test reference integrity
    for definition in definitions:
        def_id = definition.attrib['id']
        criteria = definition.findall(f'.//{{{oval_ns}}}criterion')
        for criterion in criteria:
            test_ref = criterion.attrib.get('test_ref')
            if not test_ref:
                print(f"Error: Definition {def_id} has criterion with missing test_ref.")
                errors += 1
                continue
            if test_ref not in test_ids:
                print(f"Error: Definition {def_id} references missing OVAL Test: {test_ref}")
                errors += 1
                
    # 2. Verify Test -> Object/State reference integrity
    for test in tests:
        test_id = test.attrib['id']
        # check tag namespace
        if test.tag.startswith(f"{{{win_ns}}}"):
            ns = win_ns
        elif test.tag.startswith(f"{{{ind_ns}}}"):
            ns = ind_ns
        else:
            print(f"Error: Test {test_id} has invalid namespace: {test.tag}")
            errors += 1
            continue
            
        obj_refs = test.findall(f'{{{ns}}}object')
        for obj_ref in obj_refs:
            ref = obj_ref.attrib.get('object_ref')
            if not ref or ref not in object_ids:
                print(f"Error: Test {test_id} references missing Object: {ref}")
                errors += 1
                
        ste_refs = test.findall(f'{{{ns}}}state')
        for ste_ref in ste_refs:
            ref = ste_ref.attrib.get('state_ref')
            if not ref or ref not in state_ids:
                print(f"Error: Test {test_id} references missing State: {ref}")
                errors += 1
                
    # 3. Validate against provided XSD schemas elements
    if xsd_elements:
        print("  Checking native elements against XSD schemas...")
        for category, items, ns_uri in [('test', tests, win_ns), ('object', objects, win_ns), ('state', states, win_ns)]:
            for item in items:
                tag_name = item.tag.split('}')[-1]
                # Only check elements under windows namespace
                if item.tag.startswith(f"{{{ns_uri}}}"):
                    if tag_name not in xsd_elements:
                        print(f"Error: Native {category} element '{tag_name}' (ID: {item.attrib.get('id')}) is not declared in the provided schemas.")
                        errors += 1
                    # Check child elements
                    for child in item:
                        child_name = child.tag.split('}')[-1]
                        # Don't validate standard common elements like filter or set in windows objects
                        if child.tag.startswith(f"{{{ns_uri}}}") and child_name not in xsd_elements:
                            print(f"Error: Native child element '{child_name}' under '{tag_name}' (ID: {item.attrib.get('id')}) is not declared in the schemas.")
                            errors += 1
                            
    return errors == 0, definition_ids

def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    xccdf_path = os.path.join(repo_root, 'audit', 'scap', 'ad-hardening-xccdf.xml')
    oval_path = os.path.join(repo_root, 'audit', 'scap', 'ad-hardening-oval.xml')
    
    xsd_files = [
        os.path.join(repo_root, 'windows-definitions-schema.xsd'),
        os.path.join(repo_root, 'windows-system-characteristics-schema.xsd')
    ]
    
    print("Loading XSD schemas...")
    xsd_elements = load_xsd_elements(xsd_files)
    print(f"Loaded {len(xsd_elements)} element names from schemas.\n")
    
    oval_ok, oval_definition_ids = validate_oval(oval_path, xsd_elements)
    xccdf_ok = validate_xccdf(xccdf_path, oval_definition_ids)
    
    print("\n-------------------------------------------")
    if oval_ok and xccdf_ok:
        print("Compliance Linter & Validator: PASSED!")
        sys.exit(0)
    else:
        print("Compliance Linter & Validator: FAILED!")
        sys.exit(1)

if __name__ == '__main__':
    main()
