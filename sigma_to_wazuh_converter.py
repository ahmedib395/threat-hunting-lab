#!/usr/bin/env python3
import yaml
import xml.etree.ElementTree as ET
from xml.dom import minidom
import glob
import sys

def convert_sigma_to_wazuh(sigma_file):
    """Convert a Sigma rule to Wazuh XML format"""
    with open(sigma_file, 'r') as f:
        sigma_rule = yaml.safe_load(f)
    
    rule_id = 100000 + len(glob.glob('sigma-rules/*.yml'))
    
    rule = ET.Element('rule')
    rule.set('id', str(rule_id))
    rule.set('level', str(sigma_rule.get('level', 3)))
    
    # Add if_group
    if_group = ET.SubElement(rule, 'if_group')
    if_group.text = 'sysmon_eid1_detections'
    
    # Add detection fields
    detection = sigma_rule.get('detection', {})
    if isinstance(detection, dict):
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, dict):
                for field_name, field_value in value.items():
                    field = ET.SubElement(rule, 'field')
                    field.set('name', field_name)
                    field.set('type', 'pcre2')
                    if isinstance(field_value, list):
                        field.text = '|'.join(str(v) for v in field_value)
                    else:
                        field.text = str(field_value)
    
    # Add description
    description = ET.SubElement(rule, 'description')
    description.text = sigma_rule.get('title', 'Sigma Detection Rule')
    
    return ET.tostring(rule, encoding='unicode')

if __name__ == '__main__':
    sigma_files = glob.glob('sigma-rules/*.yml')
    print(f"<group name=\"sigma_rules\">")
    for sigma_file in sigma_files:
        try:
            xml = convert_sigma_to_wazuh(sigma_file)
            print(xml)
        except Exception as e:
            print(f"Error converting {sigma_file}: {e}", file=sys.stderr)
    print("</group>")