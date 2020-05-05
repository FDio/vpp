# CRC generation

#
# Plugin entry point
#
def run(args, input_filename, s):
    output = ''
    for t in s['Define']:
        output += f'{t.name}:{t.crc:#08x}\n'
    return output
