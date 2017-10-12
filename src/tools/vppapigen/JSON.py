#### JSON generation ####
import json

def walk_enums(s):
    r = []
    for e in s:
        d = []
        d.append(e.name)
        for b in e.block:
            d.append(b)
        r.append(d)
    return r

def walk_defs(s):
    r = []
    for t in s:
        d = []
        d.append(t.name)
        for b in t.block:
            if len(b) == 3:
                if type(b[2]) is str:
                        b.insert(2, 0)
            d.append(b)
        if t.crc:
            c = {}
            c['crc'] = "{0:#0{1}x}".format(t.crc,10)
            d.append(c)

        r.append(d)
    return r

#
# Plugin entry point
#
def run(filename, s, file_crc):
    j = {}
    #j['options'] = []
    for t in s['assignments']:
        j['options'].append(t.assignment)

    j['types'] = walk_defs(s['typedefs'])
    j['messages'] = walk_defs(s['defines'])
    j['enums'] = walk_enums(s['enums'])
    j['vl_api_version'] = hex(file_crc)
        #return json.dumps(j, indent=4, separators=(',', ': '))
    return json.dumps(j, indent=4, separators=(',', ': '))
