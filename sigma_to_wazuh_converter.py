#!/usr/bin/env python3
"""
Production-grade Sigma to Wazuh XML converter
Generates deployment-ready XML with combined OR logic fields
"""

import yaml
import glob
import sys
from collections import defaultdict

class SigmaToWazuhConverter:
    def __init__(self):
        self.rule_id = 100001
    
    def convert_sigma_to_wazuh(self, sigma_file):
        """Convert Sigma YAML to Wazuh XML rule"""
        try:
            with open(sigma_file, 'r') as f:
                sigma = yaml.safe_load(f)
        except Exception as e:
            print(f"ERROR: {sigma_file}: {e}", file=sys.stderr)
            return None
        
        if not sigma:
            return None
        
        title = sigma.get('title', 'Detection Rule')
        level = sigma.get('level', 'medium')
        
        # Map levels
        level_map = {'low': 5, 'medium': 5, 'high': 10, 'critical': 10}
        wazuh_level = level_map.get(level, 5)
        
        # Start building XML
        rule_lines = []
        rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
        rule_lines.append('    <if_group>sysmon</if_group>')
        rule_lines.append('    <field name="win.system.eventID">1</field>')
        
        # Group fields by name to combine values
        field_groups = defaultdict(list)
        
        # Extract detection fields
        detection = sigma.get('detection', {})
        if isinstance(detection, dict):
            for key, value in detection.items():
                if key == 'condition':
                    continue
                if isinstance(value, dict):
                    for field_name, field_values in value.items():
                        # Normalize to list
                        if not isinstance(field_values, list):
                            field_values = [field_values]
                        
                        # Extract base field and add data. prefix
                        base_field = field_name.split('|')[0]
                        wazuh_field = f"data.win.eventdata.{base_field}" if not base_field.startswith('data.') else base_field
                        
                        # Group all values by field name
                        field_groups[wazuh_field].extend(field_values)
        
        # Output combined fields (one field per unique name with OR logic)
        for field_name in sorted(field_groups.keys()):
            values = field_groups[field_name]
            if values:
                # Escape backslashes and combine with OR
                escaped_values = [str(v).replace('\\', '\\\\') for v in values]
                pattern = '|'.join(escaped_values)
                rule_lines.append(f'    <field name="{field_name}" type="pcre2">(?i)({pattern})</field>')
        
        # Add description
        rule_lines.append(f'    <description>{title}</description>')
        rule_lines.append('  </rule>')
        
        self.rule_id += 1
        return '\n'.join(rule_lines)

def main():
    converter = SigmaToWazuhConverter()
    sigma_files = sorted(glob.glob('sigma-rules/*.yml'))
    
    if not sigma_files:
        print("ERROR: No Sigma rules found", file=sys.stderr)
        sys.exit(1)
    
    print('<group name="sigma_detection_rules">')
    
    for sigma_file in sigma_files:
        try:
            xml = converter.convert_sigma_to_wazuh(sigma_file)
            if xml:
                print(xml)
        except Exception as e:
            print(f"ERROR: {sigma_file}: {e}", file=sys.stderr)
    
    print('</group>')

if __name__ == '__main__':
    main()
