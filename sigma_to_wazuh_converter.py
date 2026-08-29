#!/usr/bin/env python3
"""
Production-Grade Sigma to Wazuh XML Converter
Automatically handles field aggregation and dynamic Sysmon group routing.
"""

import glob
import html
import os
import sys
import yaml

class SigmaToWazuhConverter:

  def __init__(self, start_rule_id=100001):
    self.rule_id = start_rule_id
    self.rules = []

    self.field_map = {
        'Image': 'win.eventdata.image',
        'CommandLine': 'win.eventdata.commandLine',
        'TargetObject': 'win.eventdata.targetObject',
        'ParentImage': 'win.eventdata.parentImage',
        'OriginalFileName': 'win.eventdata.originalFileName',
        'User': 'win.eventdata.user',
        'TargetImage': 'win.eventdata.targetImage',
        'ParentCommandLine': 'win.eventdata.parentCommandLine',
    }

    self.level_map = {
        'low': 3,
        'medium': 5,
        'high': 8,
        'critical': 12,
    }

  def escape_xml(self, text):
    return html.escape(str(text), quote=True)

  def get_escaped_patterns(self, field_name, field_values):
    """Extracts and escapes regex patterns without grouping them yet."""
    if not isinstance(field_values, list):
      field_values = [field_values]

    modifier = ''
    if '|endswith' in field_name:
      modifier = 'endswith'
    elif '|startswith' in field_name:
      modifier = 'startswith'

    patterns = []
    for val in field_values:
      val_str = str(val)

      # Escape special regex characters
      for char in ['.', '$', '^', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|']:
        val_str = val_str.replace(char, f'\\{char}')
      # Escape backslashes for PCRE2
      val_str = val_str.replace('\\', '\\\\')

      if modifier == 'endswith':
        patterns.append(f'.*{val_str}$')
      elif modifier == 'startswith':
        patterns.append(f'^{val_str}')
      else:
        patterns.append(val_str)
        
    return patterns

  def convert_sigma_to_wazuh(self, sigma_file):
    try:
      with open(sigma_file, 'r', encoding='utf-8') as f:
        sigma = yaml.safe_load(f)
    except Exception as e:
      print(f'ERROR parsing {sigma_file}: {e}', file=sys.stderr)
      return False

    if not sigma or not isinstance(sigma, dict):
      return False

    title = sigma.get('title', 'Sigma Detection Rule')
    level = str(sigma.get('level', 'medium')).lower()
    wazuh_level = self.level_map.get(level, 5)

    # 1. Aggregate Fields to Prevent AND Logic Traps
    field_patterns = {}
    has_registry = False

    detection = sigma.get('detection', {})
    if isinstance(detection, dict):
      for selector_key, selector_value in detection.items():
        if selector_key == 'condition':
          continue

        if isinstance(selector_value, dict):
          for field_name, field_values in selector_value.items():
            base_field = field_name.split('|')[0]
            wazuh_field = self.field_map.get(base_field, base_field)

            # Check for registry indicators
            if wazuh_field == 'win.eventdata.targetObject':
                has_registry = True

            patterns = self.get_escaped_patterns(field_name, field_values)
            
            if wazuh_field not in field_patterns:
                field_patterns[wazuh_field] = []
            field_patterns[wazuh_field].extend(patterns)

    # 2. Assign Correct Sysmon Group Based on Category or Field Content
    category = sigma.get('logsource', {}).get('category', '')
    if has_registry or category in ['registry_set', 'registry_add', 'registry_event']:
      group_name = 'sysmon_event13'
    elif category == 'process_access':
      group_name = 'sysmon_event10'
    else:
      group_name = 'sysmon_event1'

    # 3. Build XML Rule
    rule_lines = []
    rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
    rule_lines.append(f'    <if_group>{group_name}</if_group>')

    for wazuh_field, patterns in field_patterns.items():
        # Remove duplicate patterns and combine into a single PCRE2 group
        unique_patterns = list(dict.fromkeys(patterns))
        if len(unique_patterns) > 1:
            combined = f"(?i)({'|'.join(unique_patterns)})"
        else:
            combined = f"(?i){unique_patterns[0]}"
            
        escaped_pattern = self.escape_xml(combined)
        rule_lines.append(f'    <field name="{wazuh_field}" type="pcre2">{escaped_pattern}</field>')

    escaped_title = self.escape_xml(title)
    rule_lines.append(f'    <description>{escaped_title}</description>')
    rule_lines.append('  </rule>')

    self.rules.append('\n'.join(rule_lines))
    self.rule_id += 1
    return True

def main():
  converter = SigmaToWazuhConverter()
  sigma_files = sorted(glob.glob(os.path.join('sigma-rules', '*.yml'))) + sorted(glob.glob(os.path.join('sigma-rules', '*.yaml')))

  if not sigma_files:
    print('ERROR: No Sigma rules found in sigma-rules/', file=sys.stderr)
    sys.exit(1)

  for sigma_file in sigma_files:
    converter.convert_sigma_to_wazuh(sigma_file)

  print('<group name="sigma_detection_rules">')
  for rule in converter.rules:
    print(rule)
  print('</group>')

if __name__ == '__main__':
  main()
