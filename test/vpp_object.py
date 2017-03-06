""" abstract vpp object and object registry """

from abc import ABCMeta, abstractmethod


class VppObject(object):
    """ Abstract vpp object """
    __metaclass__ = ABCMeta

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

    def register(self, obj, logger):
        """ Register an object in the registry. """
        if obj.object_id() not in self._object_dict:
            self._object_registry.append(obj)
            self._object_dict[obj.object_id()] = obj
            logger.debug("REG: registering %s" % obj)
        else:
            logger.debug("REG: duplicate add, ignoring (%s)" % obj)

    def unregister_all(self, logger):
        """ Remove all object registrations from registry. """
        logger.debug("REG: removing all object registrations")
        self._object_registry = []
        self._object_dict = dict()

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
        for obj in reversed(self._object_registry):
            if obj.query_vpp_config():
                logger.info("REG: Removing configuration for %s" % obj)
                obj.remove_vpp_config()
            else:
                logger.info(
                    "REG: Skipping removal for %s, configuration not present" %
                    obj)
        failed = []
        for obj in self._object_registry:
            if obj.query_vpp_config():
                failed.append(obj)
        self.unregister_all(logger)
        if failed:
            logger.error("REG: Couldn't remove configuration for object(s):")
            for obj in failed:
                logger.error(repr(obj))
            raise Exception("Couldn't remove configuration for object(s): %s" %
                            (", ".join(str(x) for x in failed)))
