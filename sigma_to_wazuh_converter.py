import os
import glob
import yaml

# Wazuh ID counter starting point
START_RULE_ID = 100001

# Maps standard Sigma field names to correct Wazuh JSON/Sysmon paths
FIELD_MAPPING = {
    "Image": "win.eventdata.image",
    "OriginalFileName": "win.eventdata.originalFileName",
    "CommandLine": "win.eventdata.commandLine",
    "ParentImage": "win.eventdata.parentImage",
    "TargetObject": "win.eventdata.targetObject",
    "User": "win.eventdata.user",
    "Hashes": "win.eventdata.hashes"
}

def clean_value(val):
    """Normalizes and escapes strings for PCRE2 compatibility in Wazuh."""
    if isinstance(val, list):
        # Join lists into a regex OR group
        return "|".join([str(v).replace("\\", "\\\\") for v in val])
    elif isinstance(val, str):
        return val.replace("\\", "\\\\")
    return str(val)

def convert_yaml_to_wazuh_rule(filepath, rule_id):
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            print(f"Skipping {filepath}: Error parsing YAML ({e})")
            return None

    if not data or 'detection' not in data:
        return None

    title = data.get('title', 'Unknown Sigma Rule')
    description = data.get('description', title).strip().replace('\n', ' ')
    level = "10" # Default detection level
    
    # Determine Event ID based on detection fields or tags
    event_id = "1"
    detection = data.get('detection', {})
    
    rule_xml = f'  <!-- Rule: {title} -->\n'
    rule_xml += f'  <rule id="{rule_id}" level="{level}">\n'
    rule_xml += '    <if_group>sysmon</if_group>\n'

    # Extract fields from detection selections
    fields_content = ""
    for key, val in detection.items():
        if key == 'condition':
            continue
        if isinstance(val, dict):
            for field_key, field_val in val.items():
                # Clean field modifier if present (e.g., Image|contains -> Image)
                base_field = field_key.split('|')[0]
                wazuh_field = FIELD_MAPPING.get(base_field, f"win.eventdata.{base_field.lower()}")
                
                # Check if it targets registry (Event ID 13)
                if base_field == 'TargetObject':
                    event_id = "13"

                formatted_val = clean_value(field_val)
                fields_content += f'    <field name="{wazuh_field}" type="pcre2">(?i)({formatted_val})</field>\n'

    rule_xml += f'    <field name="win.system.eventID">{event_id}</field>\n'
    rule_xml += fields_content
    rule_xml += f'    <description>{title} - {description}</description>\n'
    rule_xml += '  </rule>\n'
    
    return rule_xml

def generate_rules_file(sigma_directory, output_xml_path):
    current_id = START_RULE_ID
    xml_output = '<group name="sigma_detection_rules">\n'
    
    search_pattern = os.path.join(sigma_directory, '**', '*.yml')
    files = glob.glob(search_pattern, recursive=True)
    
    if not files:
        # Try .yaml extension too
        search_pattern = os.path.join(sigma_directory, '**', '*.yaml')
        files = glob.glob(search_pattern, recursive=True)

    for filepath in files:
        rule_snippet = convert_yaml_to_wazuh_rule(filepath, current_id)
        if rule_snippet:
            xml_output += rule_snippet + '\n'
            current_id += 1

    xml_output += '</group>'

    with open(output_xml_path, 'w', encoding='utf-8') as out:
        out.write(xml_output)
    print(f"Successfully compiled {current_id - START_RULE_ID} rules into {output_xml_path}")

if __name__ == '__main__':
    # Point this to your repository folder containing the Sigma YAML rules
    RULES_DIR = './sigma_rules'
    OUTPUT_FILE = 'local_rules.xml'
    generate_rules_file(RULES_DIR, OUTPUT_FILE)
