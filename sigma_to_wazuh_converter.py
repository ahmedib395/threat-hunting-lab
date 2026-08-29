#!/usr/bin/env python3
import yaml
import glob
import xml.etree.ElementTree as ET
import re
import sys

class SigmaToWazuhConverter:
    def __init__(self):
        self.rule_counter = 100001
    
    def escape_field_value(self, value):
        """Escape special characters for Wazuh XML"""
        value = str(value)
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        value = value.replace('>', '&gt;')
        value = value.replace('"', '&quot;')
        value = value.replace("'", '&apos;')
        return value
    
    def convert_field_value(self, field_name, value):
        """Convert Sigma field operators to Wazuh patterns"""
        value_str = str(value)
        
        # Extract operator from field name
        if '|endswith' in field_name:
            # Regex for ending match
            escaped = re.escape(value_str)
            return f"({escaped})$"
        elif '|startswith' in field_name:
            # Regex for starting match
            escaped = re.escape(value_str)
            return f"^({escaped})"
        elif '|contains' in field_name:
            # Simple substring - pcre2 will match anywhere
            return value_str
        else:
            return value_str
    
    def convert_sigma_rule(self, yaml_file):
        """Convert single Sigma YAML to Wazuh XML rule"""
        try:
            with open(yaml_file, 'r') as f:
                sigma_rule = yaml.safe_load(f)
        except Exception as e:
            print(f"ERROR: {yaml_file}: {e}", file=sys.stderr)
            return None
        
        if not sigma_rule:
            return None
        
        rule_id = self.rule_counter
        self.rule_counter += 1
        
        # Map Sigma levels to Wazuh levels
        level_map = {'low': 3, 'medium': 4, 'high': 5, 'critical': 6}
        sigma_level = sigma_rule.get('level', 'medium')
        wazuh_level = level_map.get(sigma_level, 4)
        
        # Create rule XML element
        rule = ET.Element('rule')
        rule.set('id', str(rule_id))
        rule.set('level', str(wazuh_level))
        
        # Add required if_group
        if_group = ET.SubElement(rule, 'if_group')
        if_group.text = 'sysmon_eid1_detections'
        
        # Process detection conditions
        detection = sigma_rule.get('detection', {})
        if isinstance(detection, dict):
            for key, conditions in detection.items():
                if key == 'condition':
                    continue
                if isinstance(conditions, dict):
                    for field_name, field_values in conditions.items():
                        # Handle both single values and lists
                        values_list = field_values if isinstance(field_values, list) else [field_values]
                        
                        for val in values_list:
                            # Extract base field name (remove operators)
                            base_field = field_name.split('|')[0]
                            
                            # Create field element
                            field_elem = ET.SubElement(rule, 'field')
                            field_elem.set('name', base_field)
                            field_elem.set('type', 'pcre2')
                            field_elem.text = self.escape_field_value(
                                self.convert_field_value(field_name, val)
                            )
        
        # Add description
        description = ET.SubElement(rule, 'description')
        description.text = sigma_rule.get('title', 'Sigma Detection Rule')
        
        # Pretty print XML
        return self.prettify_xml(rule)
    
    def prettify_xml(self, elem):
        """Return pretty-printed XML string"""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = ET.fromstring(rough_string)
        return ET.tostring(reparsed, encoding='unicode')

def main():
    converter = SigmaToWazuhConverter()
    sigma_files = sorted(glob.glob('sigma-rules/*.yml'))
    
    if not sigma_files:
        print("ERROR: No Sigma rules found in sigma-rules/", file=sys.stderr)
        sys.exit(1)
    
    print('<group name="sigma_detection_rules">')
    
    for sigma_file in sigma_files:
        try:
            xml = converter.convert_sigma_rule(sigma_file)
            if xml:
                print(f"  {xml}")
        except Exception as e:
            print(f"  <!-- Error converting {sigma_file}: {e} -->", file=sys.stderr)
    
    print('</group>')

if __name__ == '__main__':
    main()