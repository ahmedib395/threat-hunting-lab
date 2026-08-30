#!/usr/bin/env python3
"""
Production-grade Sigma to Wazuh XML converter
Reads Sigma YAML rules, maps MITRE tags dynamically, escapes regex for XML,
enforces 'data.' field prefixes, and outputs to stdout + wazuh_rules.xml.
"""

import yaml
import glob
import sys
import html
from collections import defaultdict

class SigmaToWazuhConverter:
    def __init__(self):
        self.rule_id = 100001
        self.rule_counter = 1
    
    def convert_sigma_to_wazuh(self, sigma_file):
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
        
        # Map Sigma severity levels to Wazuh rule levels
        level_map = {'low': 5, 'medium': 5, 'high': 10, 'critical': 10}
        wazuh_level = level_map.get(level, 5)
        
        # Dynamically extract and format MITRE tags
        mitre_tags = []
        for tag in sigma.get('tags', []):
            if tag.startswith('attack.t'):
                mitre_tags.append(tag.replace('attack.', '').upper())
        
        mitre_prefix = f"{mitre_tags[0]}: " if mitre_tags else ""
        mitre_comment = mitre_tags[0] if mitre_tags else "Unknown"
        
        field_groups = defaultdict(list)
        event_id = '1'
        
        detection = sigma.get('detection', {})
        if isinstance(detection, dict):
            for key, value in detection.items():
                if key == 'condition':
                    continue
                if isinstance(value, dict):
                    for field_name, field_values in value.items():
                        if not isinstance(field_values, list):
                            field_values = [field_values]
                        
                        base_field = field_name.split('|')[0]
                        
                        # Dynamic Event ID switching for registry events
                        if 'targetobject' in base_field.lower():
                            event_id = '13'
                        
                        # Standard Wazuh field mapping (Enforcing data. prefix for indexed log schema)
                        b_lower = base_field.lower()
                        if b_lower == 'image':
                            wazuh_field = 'data.win.eventdata.image'
                        elif b_lower == 'commandline':
                            wazuh_field = 'data.win.eventdata.commandLine'
                        elif b_lower == 'originalfilename':
                            wazuh_field = 'data.win.eventdata.originalFileName'
                        elif b_lower == 'targetobject':
                            wazuh_field = 'data.win.eventdata.targetObject'
                        elif b_lower == 'parentimage':
                            wazuh_field = 'data.win.eventdata.parentImage'
                        elif b_lower == 'user':
                            wazuh_field = 'data.win.eventdata.User'
                        else:
                            wazuh_field = f'data.win.eventdata.{base_field}'
                        
                        field_groups[wazuh_field].extend(field_values)
        
        # Build XML rule elements
        rule_lines = []
        rule_lines.append(f'  <!-- Rule {self.rule_counter}: {mitre_comment} - {title} -->')
        rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
        rule_lines.append('    <if_group>sysmon</if_group>')
        
        # Inject dynamic MITRE mapping block for Wazuh GUI dashboard
        if mitre_tags:
            rule_lines.append('    <mitre>')
            for tag in mitre_tags:
                rule_lines.append(f'      <id>{tag}</id>')
            rule_lines.append('    </mitre>')
            
        rule_lines.append(f'    <field name="win.system.eventID">{event_id}</field>')
        
        for field_name in sorted(field_groups.keys()):
            values = field_groups[field_name]
            if values:
                escaped_values = [str(v).replace('\\', '\\\\') for v in values]
                escaped_values = [v.replace('|', '\\|') for v in escaped_values]
                pattern = '|'.join(escaped_values)
                
                # HTML escape reserved XML characters like &, <, >
                safe_xml_pattern = html.escape(pattern)
                rule_lines.append(f'    <field name="{field_name}" type="pcre2">(?i)({safe_xml_pattern})</field>')
        
        rule_lines.append(f'    <description>{mitre_prefix}{title}</description>')
        rule_lines.append('  </rule>')
        
        self.rule_id += 1
        self.rule_counter += 1
        return '\n'.join(rule_lines)

def main():
    converter = SigmaToWazuhConverter()
    sigma_files = sorted(glob.glob('sigma-rules/*.yml'))
    
    if not sigma_files:
        print("ERROR: No Sigma rules found in sigma-rules/*.yml", file=sys.stderr)
        sys.exit(1)
    
    xml_content = '<group name="sigma_detection_rules">\n'
    
    for sigma_file in sigma_files:
        try:
            xml = converter.convert_sigma_to_wazuh(sigma_file)
            if xml:
                xml_content += xml + '\n'
        except Exception as e:
            print(f"ERROR: {sigma_file}: {e}", file=sys.stderr)
    
    xml_content += '</group>'
    
    # Print output to STDOUT for pipeline logging
    print(xml_content)
    
    # Save output to wazuh_rules.xml for GitHub Artifact upload
    with open('wazuh_rules.xml', 'w') as f:
        f.write(xml_content)

if __name__ == '__main__':
    main()
