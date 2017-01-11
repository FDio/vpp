from abc import ABCMeta, abstractmethod


class VppObject(object):
    """ Abstract vpp object """
    __metaclass__ = ABCMeta

    def __init__(self):
        VppObjectRegistry().register(self)

    @abstractmethod
    def add_vpp_config(self):
        """ Add the configuration for this object to vpp. """
        pass

    @abstractmethod
    def query_vpp_config(self):
        """Query the vpp configuration.

        :return: True if the object is configured"""
        pass

    @abstractmethod
    def remove_vpp_config(self):
        """ Remove the configuration for this object from vpp. """
        pass

    @abstractmethod
    def object_id(self):
        """ Return a unique string representing this object. """
        pass


class VppObjectRegistry(object):
    """ Class which handles automatic configuration cleanup. """
    _shared_state = {}

    def __init__(self):
        self.__dict__ = self._shared_state
        if not hasattr(self, "_object_registry"):
            self._object_registry = []
        if not hasattr(self, "_object_dict"):
            self._object_dict = dict()

    def register(self, o, logger):
        """ Register an object in the registry. """
        if not o.object_id() in self._object_dict:
            self._object_registry.append(o)
            self._object_dict[o.object_id()] = o
        else:
            logger.debug("REG: duplicate add, ignoring (%s)" % o)

    def remove_vpp_config(self, logger):
        """
        Remove configuration (if present) from vpp and then remove all objects
        from the registry.
        """
        if not self._object_registry:
            logger.info("REG: No objects registered for auto-cleanup.")
            return
        logger.info("REG: Removing VPP configuration for registered objects")
        # remove the config in reverse order as there might be dependencies
        for o in reversed(self._object_registry):
            if o.query_vpp_config():
                logger.info("REG: Removing configuration for %s" % o)
                o.remove_vpp_config()
            else:
                logger.info(
                    "REG: Skipping removal for %s, configuration not present" %
                    o)
        failed = []
        for o in self._object_registry:
            if o.query_vpp_config():
                failed.append(o)
        self._object_registry = []
        self._object_dict = dict()
        if failed:
            logger.error("REG: Couldn't remove configuration for object(s):")
            for x in failed:
                logger.error(repr(x))
            raise Exception("Couldn't remove configuration for object(s): %s" %
                            (", ".join(str(x) for x in failed)))
