#!/usr/bin/env python3
"""
Production-Grade Sigma to Wazuh XML Converter
Generates valid, non-mismatching Wazuh XML rules from Sigma YAML files.
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

    # Map Sigma base field names to standard Wazuh Sysmon field names
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

    # Map Sigma threat levels to Wazuh rule levels
    self.level_map = {
        'low': 3,
        'medium': 5,
        'high': 8,
        'critical': 12,
    }

  def escape_xml(self, text):
    """Properly escape XML special characters."""
    return html.escape(str(text), quote=True)

  def format_pcre2_pattern(self, field_name, field_values):
    """
    Converts a list of values into a single PCRE2 regex group (?i)(val1|val2).
    This avoids outputting multiple <field> elements which cause AND-logic mismatches in Wazuh.
    """
    if not isinstance(field_values, list):
      field_values = [field_values]

    modifier = None
    if '|endswith' in field_name:
      modifier = 'endswith'
    elif '|startswith' in field_name:
      modifier = 'startswith'

    escaped_patterns = []
    for val in field_values:
      val_str = str(val)

      # Escape special regex characters (excluding backslashes)
      regex_chars = [
          '.',
          '$',
          '^',
          '*',
          '+',
          '?',
          '(',
          ')',
          '[',
          ']',
          '{',
          '}',
          '|',
      ]
      for char in regex_chars:
        val_str = val_str.replace(char, f'\\{char}')

      # Escape backslashes for PCRE2 path matching
      val_str = val_str.replace('\\', '\\\\')

      # Apply modifiers
      if modifier == 'endswith':
        escaped_patterns.append(f'.*{val_str}$')
      elif modifier == 'startswith':
        escaped_patterns.append(f'^{val_str}')
      else:
        escaped_patterns.append(val_str)

    # Combine using PCRE2 case-insensitive OR logic
    if len(escaped_patterns) > 1:
      return f"(?i)({'|'.join(escaped_patterns)})"
    else:
      return f'(?i){escaped_patterns[0]}'

  def get_wazuh_group(self, sigma):
    """
    Dynamically maps logsource categories to native Wazuh Sysmon rule groups.
    """
    category = sigma.get('logsource', {}).get('category', '')
    if category == 'process_creation':
      return 'sysmon_event1'  # Standard Wazuh Sysmon Event ID 1 group
    elif category in ['registry_set', 'registry_add', 'registry_event']:
      return 'sysmon_event13'  # Standard Wazuh Sysmon Event ID 12/13/14 group
    elif category == 'process_access':
      return 'sysmon_event10'  # Standard Wazuh Sysmon Event ID 10 group
    return 'sysmon_event1'  # Fallback group

  def convert_sigma_to_wazuh(self, sigma_file):
    """
    Parses a single Sigma YAML file and formats it into a Wazuh XML rule block.
    """
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
    group_name = self.get_wazuh_group(sigma)

    rule_lines = []
    rule_lines.append(f'  <rule id="{self.rule_id}" level="{wazuh_level}">')
    rule_lines.append(f'    <if_group>{group_name}</if_group>')

    detection = sigma.get('detection', {})
    if isinstance(detection, dict):
      for selector_key, selector_value in detection.items():
        if selector_key == 'condition':
          continue

        if isinstance(selector_value, dict):
          for field_name, field_values in selector_value.items():
            base_field = field_name.split('|')[0]
            wazuh_field = self.field_map.get(base_field, base_field)

            pcre2_pattern = self.format_pcre2_pattern(
                field_name, field_values
            )
            escaped_pattern = self.escape_xml(pcre2_pattern)

            rule_lines.append(
                f'    <field name="{wazuh_field}"'
                f' type="pcre2">{escaped_pattern}</field>'
            )

    escaped_title = self.escape_xml(title)
    rule_lines.append(f'    <description>{escaped_title}</description>')
    rule_lines.append('  </rule>')

    self.rules.append('\n'.join(rule_lines))
    self.rule_id += 1
    return True


def main():
  converter = SigmaToWazuhConverter()

  # Search for .yml or .yaml files in the sigma-rules folder
  sigma_files = sorted(glob.glob(os.path.join('sigma-rules', '*.yml'))) + sorted(
      glob.glob(os.path.join('sigma-rules', '*.yaml'))
  )

  if not sigma_files:
    print('ERROR: No Sigma rules found in sigma-rules/', file=sys.stderr)
    sys.exit(1)

  converted_count = 0
  for sigma_file in sigma_files:
    if converter.convert_sigma_to_wazuh(sigma_file):
      converted_count += 1

  if converted_count == 0:
    print('ERROR: No rules were converted successfully', file=sys.stderr)
    sys.exit(1)

  # Output the final XML structure
  print('<group name="sigma_detection_rules">')
  for rule in converter.rules:
    print(rule)
  print('</group>')


if __name__ == '__main__':
  main()
