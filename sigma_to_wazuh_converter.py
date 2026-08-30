#!/usr/bin/env python3
"""
Production-grade Sigma to Wazuh XML converter
Reads Sigma YAML rules and generates deployment-ready Wazuh XML file
"""

import yaml
import glob
import sys
from collections import defaultdict

class SigmaToWazuhConverter:
    def __init__(self):
        self.rule_id = 100001
    
    def convert_sigma_to_wazuh(self, sigma_file):
        """Convert a single Sigma YAML file to Wazuh XML"""
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
        
        # Map Sigma levels to Wazuh levels
        level_map = {'low': 5, 'medium': 5, 'high': 10, 'critical': 10}
        wazuh_level = level_map.get(level, 5)
        
        # Collect all fields grouped by name
        field_groups = defaultdict(list)
        event_id = '1'  # Default to Event ID 1
        
        # Extract detection fields from Sigma rule
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
                        
                        # Extract base field name
                        base_field = field_name.split('|')[0]
                        
                        # Detect Registry rules (Event ID 13)
                        if 'targetobject' in base_field.lower():
                            event_id = '13'
                        
                        # Add data. prefix
                        wazuh_field = f'data.win.eventdata.{base_field}'
                        
                        # Collect values
                        field_groups[wazuh_field].extend(field_values)
        
        # Build XML
        rule_lines = []
        rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
        rule_lines.append('    <if_group>sysmon</if_group>')
        rule_lines.append(f'    <field name="win.system.eventID">{event_id}</field>')
        
        # Output combined fields
        for field_name in sorted(field_groups.keys()):
            values = field_groups[field_name]
            if values:
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
    
    # Build complete XML
    xml_content = '<group name="sigma_detection_rules">\n'
    
    for sigma_file in sigma_files:
        try:
            xml = converter.convert_sigma_to_wazuh(sigma_file)
            if xml:
                xml_content += xml + '\n'
        except Exception as e:
            print(f"ERROR: {sigma_file}: {e}", file=sys.stderr)
    
    xml_content += '</group>'
    
    # Write to file
    with open('wazuh_rules.xml', 'w') as f:
        f.write(xml_content)
    
    print("✓ Generated wazuh_rules.xml successfully")

if __name__ == '__main__':
    main()
