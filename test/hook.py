from logging import *

class Hook(object):
    """
    Generic hooks before/after API/CLI calls
    """

    def before_api(self, api_name, api_args):
        """
        Function called before API call
        Emit a debug message describing the API name and arguments

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """
        debug("API: %s (%s)" % (api_name, api_args))

    def after_api(self, api_name, api_args):
        """
        Function called after API call

        @param api_name: name of the API
        @param api_args: tuple containing the API arguments
        """
        pass

    def before_cli(self, cli):
        """
        Function called before CLI call
        Emit a debug message describing the CLI

        @param cli: CLI string
        """
        debug("CLI: %s" % (cli))

    def after_cli(self, cli):
        """ 
        Function called after CLI call
        """
        pass

