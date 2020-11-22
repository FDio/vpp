# JSON generation
import json

process_imports = True


def walk_imports(s):
    r = []
    for e in s:
        r.append(str(e))
    return r


def walk_counters(s, pathset):
    r = []
    for e in s:
        r2 = {'name': e.name, 'elements': e.block}
        r.append(r2)

    r3 = []
    for p in pathset:
        r3.append(p.paths)

    return r, r3


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
        if e.stream_message:
            d['stream_msg'] = e.stream_message
        if e.events:
            d['events'] = e.events
        r[e.caller] = d
    return r


def walk_defs(s, is_message=False):
    r = []
    for t in s:
        d = []
        d.append(t.name)
        for b in t.block:
            if b.type == 'Option':
                continue
            if b.type == 'Field':
                if b.limit:
                    d.append([b.fieldtype, b.fieldname, b.limit])
                else:
                    d.append([b.fieldtype, b.fieldname])
            elif b.type == 'Array':
                if b.lengthfield:
                    d.append([b.fieldtype, b.fieldname,
                              b.length, b.lengthfield])
                else:
                    d.append([b.fieldtype, b.fieldname, b.length])
            elif b.type == 'Union':
                pass
            else:
                raise ValueError("Error in processing array type %s" % b)

        if is_message and t.crc:
            c = {}
            c['crc'] = "{0:#0{1}x}".format(t.crc, 10)
            d.append(c)

        r.append(d)
    return r


#
# Plugin entry point
#
def run(args, filename, s):
    j = {}

    j['types'] = (walk_defs([o for o in s['types']
                             if o.__class__.__name__ == 'Typedef']))
    j['messages'] = walk_defs(s['Define'], True)
    j['unions'] = (walk_defs([o for o in s['types']
                              if o.__class__.__name__ == 'Union']))
    j['enums'] = (walk_enums([o for o in s['types']
                              if o.__class__.__name__ == 'Enum']))
    j['enumflags'] = (walk_enums([o for o in s['types']
                                  if o.__class__.__name__ == 'EnumFlag']))
    j['services'] = walk_services(s['Service'])
    j['options'] = s['Option']
    j['aliases'] = {o.name:o.alias for o in s['types'] if o.__class__.__name__ == 'Using'}
    j['vl_api_version'] = hex(s['file_crc'])
    j['imports'] = walk_imports(i for i in s['Import'])
    j['counters'], j['paths'] = walk_counters(s['Counters'], s['Paths'])
    return json.dumps(j, indent=4, separators=(',', ': '))
