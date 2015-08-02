# Copyright (c) 2009-2010, Berend-Jan "SkyLined" Wever <berendjanwever@gmail.com>
# Project homepage: http://code.google.com/p/w32-dl-loadlib-shellcode/
# All rights reserved. See COPYRIGHT.txt for details.
import os, re, sys

LOCAL_PATH = os.path.dirname(sys.argv[0])


def HashXORSUB8(function_name, xor_value, start_value):
  hash = start_value;
  function_name += '\0';
  for char in function_name:
    xorred_char = ord(char) ^ xor_value;
    hash = (hash - xorred_char) & 0xFF;
  return hash;

def OutputXORSUB8(module, function_name, xor_value, start_value):
  if module is None:
    return [
      '%-39s equ 0x%02X' % ('hash_start_value', start_value),
      '%-39s equ 0x%02X' % ('hash_xor_value', xor_value),
    ];
  else:
    hash = HashXORSUB8(function_name, xor_value, start_value);
    return [
      '%-39s equ 0x%02X' % ('hash_%s_%s' % (module, function_name), hash),
    ];

def HashXORROR16(function_name, ror_value):
  hash = 0;
  function_name += '\0';
  for char in function_name:
    hash ^= ord(char);
    hash = ((hash >> ror_value) | (hash << (16 - ror_value))) & 0xFFFF;
  return hash;

def OutputXORROR16(module, function_name, ror_value):
  if module is None:
    return [
      '%-39s equ 0x%02X' % ('hash_ror_value', ror_value),
    ];
  else:
    hash = HashXORROR16(function_name, ror_value);
    return [
      '%-39s equ 0x%04X' % ('hash_%s_%s' % (module, function_name), hash),
    ];

def ReportHashes(order_of_modules, exports, functions_to_hash, output_function, hash_function, hash_function_args, 
    collision_level):
  lines = [];
  lines.append(';-- Hash function configuration --------------------------------------------');
  lines.extend(output_function(None, None, *hash_function_args));
  lines.append(';-- Function hashes --------------------------------------------------------');
  for module, function in functions_to_hash:
    lines.extend(output_function(module, function, *hash_function_args));
  lines.append(';-- Warnings ---------------------------------------------------------------');
  for module, function in functions_to_hash:
    function_hash = hash_function(function, *hash_function_args);
    lines.extend(CheckExport(order_of_modules, exports, module, function));
    lines.extend(CheckCollisions(order_of_modules, exports, module, function, function_hash,
        hash_function, hash_function_args, collision_level, full_scan=True));
  return lines;

def PrintLines(lines):
  for line in lines:
    print line;

def CheckHashes(order_of_modules, exports, functions_to_hash, hash_function, hash_function_args, collision_level):
  for module, function in functions_to_hash:
    CheckExport(order_of_modules, exports, module, function);
    function_hash = hash_function(function, *hash_function_args);
    collisions = CheckCollisions(order_of_modules, exports, module, function, function_hash,
        hash_function, hash_function_args, collision_level, full_scan=False);
    if collisions:
      return False;
  return True;

def CheckExport(order_of_modules, exports, module, function):
  found_export = False;
  lines = [];
  for module_version in exports[module]:
    if function in exports[module][module_version]['forwards']:
      forward_module, forward_function = exports[module][module_version]['forwards'][function];
      lines.append('; Warning: %s!%s forwards to %s!%s in %s.' % \
          (module, function, forward_module, forward_function, module_version));
    elif function not in exports[module][module_version]['exports']:
      lines.append('; Warning: %s!%s is not exported in %s.' % (module, function, module_version));
    else:
      found_export = True;
  if not found_export:
    print '*** Error: %s!%s is not exported in any version of the module.' % (module, function)
    exit(1);
  return lines;

def CheckCollisions(order_of_modules, exports, module, function, function_hash, 
    hash_function, hash_function_args, collision_level, full_scan):
  lines = [];
  if collision_level == 'module':
    modules = [module];
  elif collision_level == 'all':
    modules = order_of_modules;
  else:
    raise AssertionError('Unknown collision level %s!?' % collision_level)
  for other_module in modules:
    for other_module_version in exports[other_module]:
      for other_function in exports[other_module][other_module_version]['order']:
        if module == other_module and function == other_function:
          return lines; # By now the code will have found the right function
          # any collisions that could occur if the code kept on scanning are of
          # no interest.
        if function_hash == hash_function(other_function, *hash_function_args):
          lines.append('; Warning: %s!%s collides with export %s!%s.' % \
              (module, function, other_module, other_function));
          if not full_scan:
            return lines;
  raise AssertionError('Couldn\'t find "%s!%s"!?' % (module, function))

def AddExports(exports, module_name, module_version, file_path):
  if module_name not in exports:
    exports[module_name] = {};
  if module_version not in exports[module_name]:
    exports[module_name][module_version] = {'exports': [], 'forwards': {}, 'order': []};
  module_exports = exports[module_name][module_version]['exports'];
  module_forwards = exports[module_name][module_version]['forwards'];
  module_order = exports[module_name][module_version]['order'];
  file_handle = open(file_path, 'rb');
  try:
    in_header = True;
    line_index = 0;
    for line in file_handle:
      line_index += 1;
      if re.match(r'^\s*[\r\n]*$', line): 
        continue; # Empty lines are ignored
      if in_header:
        if re.match(r'^\s*ordinal\s+hint\s+RVA\s+name\s*[\r\n]*$', line):
          in_header = False;              # end of header
      elif re.match(r'^\s*Summary\s*[\r\n]*$', line):
        break;                            # start of footer
      else:
        export_match = re.match(r'^.{11} .{4} \w{8} (\w+)(?: = .*)?\s*[\r\n]*$', line);
        if export_match:
          export = export_match.group(1);
          module_exports.append(export);
          module_order.append(export);
          continue;
        none_match = re.match(r'^.{11}      \w{8} .*\s*[\r\n]*$', line);
        if none_match:
          continue;                       # Not a real export
        forward_match = re.match(r'^.{11} .{4}          (\w+) \(forwarded to ([A-Za-z0-9_-]+)\.(\w+)\)\s*[\r\n]*$', line);
        if forward_match:
          forward = forward_match.group(1);
          target_module = forward_match.group(2);
          target_function = forward_match.group(3);
          module_forwards[forward] = (target_module, target_function);
          module_order.append(forward);
          continue;
        print 'Unknown syntax in "%s":' % file_path;
        print 'Line #%d: %s' % (line_index, repr(line));
        return False;
    print '  + %s (%s): %d exports, %s forwards.' % (module_name, module_version, 
        len(module_exports), len(module_forwards));
    return True;
  finally:
    file_handle.close();

HASH_FUNCTION_INFO_TABLE = {
  'XORSUB8F':  {'hash': HashXORSUB8,  'output': OutputXORSUB8,  'dir': 1,  'arg': [range(1, 256), range(1, 256)]},
  'XORSUB8B':  {'hash': HashXORSUB8,  'output': OutputXORSUB8,  'dir': -1, 'arg': [range(1, 256), range(1, 256)]},
  'XORROR16F': {'hash': HashXORROR16, 'output': OutputXORROR16, 'dir': 1,  'arg': [range(1, 16)]},
  'XORROR16B': {'hash': HashXORROR16, 'output': OutputXORROR16, 'dir': -1, 'arg': [range(1, 16)]},
};

def Main():
  order_of_modules = [];
  functions_to_hash = [];
  input_file_name = None;
  output_file_name = None;
  hash_function_arguments = [];
  for arg in sys.argv[1:]:
    if arg.lower() == '--help':
      assert NotImplementedError('hehe, sorry :)');
    elif arg.lower().startswith('--input='):
      input_file_name = arg[len('--input='):];
    elif arg.lower().startswith('--output='):
      output_file_name = arg[len('--output='):];
    else:
      hash_function_arguments.append(arg);
  if not input_file_name:
    print 'Please specify an input file using the "--input" argument.';
    return False;
  print 'Loading config file "%s"...' % input_file_name;
  file_handle = open(input_file_name, 'rb');
  try:
    section = None;
    hash_function_name = None;
    hash_function_info = None;
    collision_level = 'all';
    header = None;
    line_index = 0;
    for line in file_handle:
      line_index += 1;
      if not header:
        header = line;
        if not header.lower().startswith('; hash v1.0 config file'):
          print 'Syntax error in config file: missing header.';
          print 'Line #%d: %s' % (line_index, repr(line));
          return False;
        else:
          continue;
      if line[1] == ';':
        # Comments
        continue;
      section_match = re.match(r'^\[(modules|functions|hash function|collision level)\]\s*[\r\n]*$', line);
      if section_match:
        section = section_match.group(1);
        continue;
      elif not section:
        print 'Syntax error in config file: missing section header.';
        print 'Line #%d: %s' % (line_index, repr(line));
        return False;
      if section == 'modules':
        module_match = re.match(r'^\s*(\w+)\s*[\r\n]*$', line)
        if not module_match:
          print 'Syntax error in config file: cannot parse "modules" line.';
          print 'Line #%d: %s' % (line_index, repr(line));
          return False;
        order_of_modules.append(module_match.group(1));
      elif section == 'functions':
        export_match = re.match(r'^\s*(\w+)!(\w+)\s*[\r\n]*$', line)
        if not export_match:
          print 'Syntax error in config file: cannot parse "functions" line.';
          print 'Line #%d: %s' % (line_index, repr(line));
          return False;
        module = export_match.group(1)
        function = export_match.group(2)
        functions_to_hash += [(module, function)]
      elif section == 'hash function':
        hash_function_match = re.match(r'^\s*(\w+)\s*[\r\n]*$', line)
        if not hash_function_match:
          print 'Syntax error in config file: cannot parse "hash function" line.';
          print 'Line #%d: %s' % (line_index, repr(line));
          return False;
        if hash_function_name:
          print 'Error in config file: multiple hash functions (previous value: "%s").' % hash_function_name;
          print 'Line #%d: %s' % (line_index, repr(line));
        hash_function_name = hash_function_match.group(1)
        if hash_function_name not in HASH_FUNCTION_INFO_TABLE.keys():
          print 'Error in config file: unknown hash function "%s".' % hash_function_name;
          print 'Line #%d: %s' % (line_index, repr(line));
          print 'Valid hash functions:';
          for hash_function_name in HASH_FUNCTION_INFO_TABLE.keys():
            print ' + "%s"' % hash_function_name;
          return False;
          
        hash_function_info = HASH_FUNCTION_INFO_TABLE[hash_function_name]
      elif section == 'collision level':
        collision_level_match = re.match(r'^\s*(\w+)\s*[\r\n]*$', line)
        assert collision_level_match, 'Cannot parse collision level line: %s' % repr(line)
        collision_level = collision_level_match.group(1).lower()
  finally:
    file_handle.close()
  if not hash_function_info:
    print 'Error in config file: missing hash function.';
    return False;

  print;
  print '  Modules in load order:';
  for module in order_of_modules:
    print '    %s' % module;
  print '  Functions to hash:';
  for (module, function) in functions_to_hash:
    print '    %s!%s' % (module, function);
  print '  Hash function:';
  print '    %s' % hash_function_name;
  print '  Collision level:';
  print '    %s' % collision_level;

  print;
  print 'Loading module information:'
  exports = {};
  dumpbin_exports_path = os.path.join(LOCAL_PATH, 'dumpbin exports');
  for file_name in os.listdir(dumpbin_exports_path):
    file_path = os.path.join(dumpbin_exports_path, file_name);
    if not os.path.isfile(file_path): continue # skip directories
    dumpbin_exports_match = re.match(r'^dumpbin exports - (\w+)\s+\((.+)\)\.txt$', file_name);
    if not dumpbin_exports_match:
      continue;     # skip files that don't contain exports
    module_name = dumpbin_exports_match.group(1);
    module_version = dumpbin_exports_match.group(2);
    if module_name in order_of_modules:
      if not AddExports(exports, module_name, module_version, file_path):
        return False;

  for module, function in functions_to_hash:
    assert module in order_of_modules, 'Module %s is not mentioned in the [modules] section.' % module;
    assert module in exports, 'No export information for module "%s" is available.' % module;
  for module in order_of_modules:
    assert module in exports, 'No export information for module "%s" is available.' % module;

  print;
  print 'Attempting to find a set of hashes that does not collide:';
  hash_function = hash_function_info['hash'];
  output_function = hash_function_info['output'];
  hash_direction = hash_function_info['dir'];
  # If this hashing function searches the module's exported function list from end to start, we'll reverse our
  # list with the order of functions to do the same:
  if hash_direction < 0:
    for module in exports:
      for module_version in exports[module]:
        exports[module][module_version]['order'].reverse();
  if hash_function_arguments:
    if len(hash_function_arguments) != len(hash_function_info['arg']):
      print >>sys.stderr, 'Hash function takes %d arguments, you provided %d.' % \
          (len(hash_function_info['arg']), len(hash_function_arguments));
      return False;
    arguments = range(len(hash_function_info['arg']));
    for i in range(len(hash_function_arguments)):
      try:
        arguments[i] = int(hash_function_arguments[i], 16);
      except ValueError, e:
        print >>sys.stderr, 'Invalid argument %s.' % hash_function_arguments[i];
        exit(1);
    PrintLines(ReportHashes(order_of_modules, exports, functions_to_hash, output_function, hash_function, arguments, collision_level));
  elif len(hash_function_info['arg']) == 0:
    arguments = ();
    if CheckHashes(order_of_modules, exports, functions_to_hash, hash_function, arguments, collision_level):
      print 'Succes!';
      PrintLines(ReportHashes(order_of_modules, exports, functions_to_hash, output_function, hash_function, arguments, collision_level));
    else:
      print 'Failed! Cannot find a suitable hashing algorithm'
  else:
    # Create arguments list and initialize all arguments to lowest value
    arguments = range(len(hash_function_info['arg']))
    for argc in range(len(hash_function_info['arg'])):
      init = hash_function_info['arg'][argc][0]
      arguments[argc] = init
    while True:
      hex_arguments = ['0x%02X' % i for i in arguments if True];
      print 'Checking %s(%s)\r' % (hash_function_name, ', '.join(hex_arguments)),
      if CheckHashes(order_of_modules, exports, functions_to_hash, hash_function, arguments, collision_level):
        print;
        print 'Succes!';
        output_lines = ReportHashes(order_of_modules, exports, functions_to_hash, output_function, hash_function, arguments, collision_level);
        if output_file_name:
          print 'Writing results to file "%s":' % output_file_name;
          output_string = '\r\n'.join(output_lines) + '\r\n';
          output_file_handle = open(output_file_name, 'w');
          try:
            output_file_handle.write(output_string);
          finally:
            output_file_handle.close();
          print '  Wrote %d bytes.' % len(output_string);
        else:
          PrintLines(output_lines);
        break;
      for argc in range(len(hash_function_info['arg'])):
        arg_range = hash_function_info['arg'][argc];
        next_range_index = arg_range.index(arguments[argc]) + 1;
        if next_range_index == len(arg_range):
          # We passed the max value: reset and increase next argument
          arguments[argc] = arg_range[0];
        else:
          # Increase this argument and try
          arguments[argc] = arg_range[next_range_index];
          break;
    else:
      print;
      print 'Failed! Cannot find a suitable hashing algorithm';
      return False;
  return True;

if __name__ == '__main__':
  import sys;
  if not Main():
    sys.exit(-1);
