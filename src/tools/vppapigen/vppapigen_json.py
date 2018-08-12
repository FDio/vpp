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
        try:
            if t.typedef_alias == True:
                f = t.block
                d.append(f)
        except:
            pass
        if type(t.block) is list:
            for b in t.block:
                f = []
                if b.type == 'Field':
                    f = [b.fieldtype, b.fieldname]
                elif b.type == 'Array':
                    if b.lengthfield:
                        f = [b.fieldtype, b.fieldname, b.length, b.lengthfield]
                    else:
                        f = [b.fieldtype, b.fieldname, b.length]
                elif b.type == 'Union':
                    pass
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

    j['types'] = walk_defs([o for o in s['types'] if o.__class__.__name__ == 'Typedef'])
    j['messages'] = walk_defs(s['Define'])
    j['unions'] = walk_defs([o for o in s['types'] if o.__class__.__name__ == 'Union'])
    j['enums'] = walk_enums([o for o in s['types'] if o.__class__.__name__ == 'Enum'])
    j['services'] = walk_services(s['Service'])
    j['vl_api_version'] = hex(file_crc)
    return json.dumps(j, indent=4, separators=(',', ': '))
