# JSON generation
import json


def walk_enums(s):
    r = []
    for e in s:
        d = []
        d.append(e.name)
        for b in e.block:
            d.append(b)
        d.append({'enumtype': e.enumtype})
        r.append(d)
    return r


def walk_services(s):
    r = {}
    for e in s:
        d = {'reply': e.reply}
        if e.stream:
            d['stream'] = True
        if e.events:
            d['events'] = e.events
        r[e.caller] = d
    return r


def walk_defs(s):
    r = []
    for t in s:
        d = []
        d.append(t.name)
        for b in t.block:
            f = []
            if b.type == 'Field':
                f = [b.fieldtype, b.fieldname]
            elif b.type == 'Array':
                if b.lengthfield:
                    f = [b.fieldtype, b.fieldname, b.length, b.lengthfield]
                else:
                    f = [b.fieldtype, b.fieldname, b.length]
            else:
                raise ValueError("Error in processing array type %s" % b)
            d.append(f)
        if t.crc:
            c = {}
            c['crc'] = "{0:#0{1}x}".format(t.crc, 10)
            d.append(c)

        r.append(d)
    return r


#
# Plugin entry point
#
def run(filename, s, file_crc):
    j = {}

    j['types'] = walk_defs(s['typedefs'])
    j['messages'] = walk_defs(s['defines'])
    j['enums'] = walk_enums(s['enums'])
    j['services'] = walk_services(s['services'])
    j['vl_api_version'] = hex(file_crc)
    return json.dumps(j, indent=4, separators=(',', ': '))
