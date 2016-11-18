from abc import abstractmethod, ABCMeta


class VppObject(object):
    """ abstract vpp object """
    __metaclass__ = ABCMeta

    @abstractmethod
    def add_vpp_config(self):
        """ Add the configuration for this object to vpp """
        pass

    @abstractmethod
    def query_vpp_config(self):
        """Query the vpp configuration

        :return: True if the object is configured"""
        pass

    @abstractmethod
    def remove_vpp_config(self):
        """ Remove the configuration for this object from vpp """
        pass


class VppObjectRegistry(object):
    """ Class which handles automatic configuration cleanup. """
    __metaclass__ = ABCMeta

    @abstractmethod
    def __init__(self):
        pass

    @classmethod
    def register(cls, o):
        """ Register an object in the registry. """
        if not hasattr(cls, "_object_registry"):
            cls._object_registry = []
        cls._object_registry.append(o)

    @classmethod
    def remove_vpp_config(cls):
        """
        Remove configuration (if present) for all objects in the registry.
        """
        if not hasattr(cls, "_object_registry"):
            cls.logger.info("No objects registered for auto-cleanup.")
            return
        cls.logger.info("Removing VPP configuration for registered objects")
        for o in reversed(cls._object_registry):
            if o.query_vpp_config():
                cls.logger.info("Removing %s", o)
                o.remove_vpp_config()
            else:
                cls.logger.info("Skipping %s, configuration not present", o)
        failed = []
        for o in cls._object_registry:
            if o.query_vpp_config():
                failed.append(o)
        if failed:
            cls.logger.error("Couldn't remove configuration for object(s):")
            for x in failed:
                cls.logger.error(repr(x))
            raise Exception("Couldn't remove configuration for object(s): %s" %
                            (", ".join(str(x) for x in failed)))
