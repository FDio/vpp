""" VRF Status codes """

from util import NumericConstant


class VRFState(NumericConstant):
    """ VRF State """
    not_configured = 0
    configured = 1
    reset = 2

    desc_dict = {
        not_configured: "VRF not configured",
        configured: "VRF configured",
        reset: "VRF reset",
    }

    def __init__(self, value):
        NumericConstant.__init__(self, value)
