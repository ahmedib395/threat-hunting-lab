#!/usr/bin/env python3
"""
Production-grade Sigma to Wazuh XML converter
Generates properly formatted XML ready for Wazuh deployment
"""

import yaml
import glob
import sys
import html

class SigmaToWazuhConverter:
    def __init__(self):
        self.rule_id = 100001
        self.rules = []
    
    def escape_xml(self, text):
        """Properly escape XML special characters"""
        return html.escape(str(text), quote=True)
    
    def convert_field_value(self, field_name, value):
        """Convert Sigma field operators to Wazuh-compatible regex"""
        value_str = str(value)
        
        # For endswith, add regex anchor
        if '|endswith' in field_name:
            return f".*{value_str.replace(chr(92), chr(92)+chr(92))}$"
        # For startswith, add regex anchor
        elif '|startswith' in field_name:
            return f"^{value_str}"
        # For contains|any, just escape backslashes properly
        elif '|contains' in field_name or '|all' in field_name:
            return value_str.replace('\\', '\\\\')
        else:
            return value_str
    
    def convert_sigma_to_wazuh(self, sigma_file):
        """Convert a single Sigma YAML file to Wazuh rule XML"""
        try:
            with open(sigma_file, 'r') as f:
                sigma = yaml.safe_load(f)
        except Exception as e:
            print(f"ERROR parsing {sigma_file}: {e}", file=sys.stderr)
            return False
        
        if not sigma:
            return False
        
        # Get rule metadata
        title = sigma.get('title', 'Sigma Detection Rule')
        level = sigma.get('level', 'medium')
        
        # Map Sigma levels to Wazuh levels
        level_map = {'low': 3, 'medium': 4, 'high': 5, 'critical': 6}
        wazuh_level = level_map.get(level, 4)
        
        # Build the rule
        rule_lines = []
        rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
        rule_lines.append('    <if_group>sysmon_eid1_detections</if_group>')
        
        # Process detection fields
        detection = sigma.get('detection', {})
        if isinstance(detection, dict):
            for key, value in detection.items():
                if key == 'condition':
                    continue
                
                if isinstance(value, dict):
                    # Handle field conditions
                    for field_name, field_values in value.items():
                        # Normalize to list
                        if not isinstance(field_values, list):
                            field_values = [field_values]
                        
                        # Extract base field name
                        base_field = field_name.split('|')[0]
                        
                        # Add field element for each value
                        for field_value in field_values:
                            converted_value = self.convert_field_value(field_name, field_value)
                            escaped_value = self.escape_xml(converted_value)
                            rule_lines.append(f'    <field name="{base_field}" type="pcre2">{escaped_value}</field>')
        
        # Add description
        escaped_title = self.escape_xml(title)
        rule_lines.append(f'    <description>{escaped_title}</description>')
        rule_lines.append('  </rule>')
        
        # Store the formatted rule
        self.rules.append('\n'.join(rule_lines))
        self.rule_id += 1
        return True

def main():
    converter = SigmaToWazuhConverter()
    sigma_files = sorted(glob.glob('sigma-rules/*.yml'))
    
    if not sigma_files:
        print("ERROR: No Sigma rules found in sigma-rules/", file=sys.stderr)
        sys.exit(1)
    
    # Convert all Sigma files
    converted_count = 0
    for sigma_file in sigma_files:
        if converter.convert_sigma_to_wazuh(sigma_file):
            converted_count += 1
    
    if converted_count == 0:
        print("ERROR: No rules were converted successfully", file=sys.stderr)
        sys.exit(1)
    
    # Output properly formatted XML
    print('<group name="sigma_detection_rules">')
    for rule in converter.rules:
        print(rule)
    print('</group>')

if __name__ == '__main__':
    main()