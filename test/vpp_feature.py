from vpp_papi_provider import VppPapiProvider


class VppFeature:
    """ Class to hold feature specific APIs and Enums
        that are not bound to VppInterface or VppObject
    """

    _vapi = None

    @classmethod
    def init_feature_class(cls, vapi):
        """Initialize feature class attributes.

        :param vapi: Vpp Papi Provider
        """
        cls._vapi = vapi

    @classmethod
    def get_vapi(cls):
        """ Returns vapi if valid."""
        if not isinstance(cls._vapi, VppPapiProvider):
            raise ValueError("No valid papi provider configured")
        return cls._vapi
