import os
import util
from string import Template

from util import remove_suffix

callback_suffix = "Callback"

callback_template = Template("""
package $base_package.$callback_package;

/**
* $docs
*/
public interface $cls_name extends $base_package.$callback_package.JVppCallback {

    $callback_method

}
""")

global_callback_template = Template("""
package $base_package.$callback_package;

/**
* Global aggregated callback interface
*/
public interface JVppGlobalCallback extends $callbacks {
}
""")


def generate_callbacks(func_list, base_package, callback_package, dto_package):
    """ Generates callback interfaces """
    print "Generating Callback interfaces"

    if not os.path.exists(callback_package):
        raise Exception("%s folder is missing" % callback_package)

    callbacks = []
    for func in func_list:

        if util.is_notification(func['name']) or util.is_ignored(func['name']):
            # FIXME handle notifications
            continue

        camel_case_name_with_suffix = util.underscore_to_camelcase_upper(func['name'])
        if not util.is_reply(camel_case_name_with_suffix):
            continue

        camel_case_name = util.remove_reply_suffix(camel_case_name_with_suffix)
        callbacks.append("{0}.{1}.{2}".format(base_package, callback_package, camel_case_name + callback_suffix))
        callback_path = os.path.join(callback_package, camel_case_name + callback_suffix + ".java")
        callback_file = open(callback_path, 'w')

        reply_type = "%s.%s.%s" % (base_package, dto_package, camel_case_name_with_suffix)
        method = "void on{0}({1} reply);".format(camel_case_name_with_suffix, reply_type)
        callback_file.write(
            callback_template.substitute(docs='Generated from ' + str(func),
                                         cls_name=camel_case_name + callback_suffix,
                                         callback_method=method,
                                         base_package=base_package,
                                         callback_package=callback_package))
        callback_file.flush()
        callback_file.close()

    callback_file = open(os.path.join(callback_package, "JVppGlobalCallback.java"), 'w')
    callback_file.write(global_callback_template.substitute(callbacks=", ".join(callbacks),
                                                            base_package=base_package,
                                                            callback_package=callback_package))
    callback_file.flush()
    callback_file.close()


