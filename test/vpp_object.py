""" abstract vpp object and object registry """

import abc
import weakref
import six


@six.add_metaclass(abc.ABCMeta)
class VppObject(object):
    """ Abstract vpp object """
    ignore_removal_failure = False

    def __init__(self, parent=None):
        self._parent = None
        if parent is not None:
            self.add_parent(parent)
        self.children = weakref.WeakSet()

    def add_parent(self, parent):
        if self._parent is not None:
            raise RuntimeError("Remove existing parent first.")
        self._parent = parent
        self._parent.children.add(self)

    @abc.abstractmethod
    def add_vpp_config(self) -> None:
        """ Add the configuration for this object to vpp. """
        pass

    @abc.abstractmethod
    def query_vpp_config(self) -> bool:
        """Query the vpp configuration.

        :return: True if the object is configured"""
        pass

    @abc.abstractmethod
    def remove_vpp_config(self) -> None:
        """ Remove the configuration for this object from vpp. """
        pass

    def object_id(self) -> str:
        """ Return a unique string representing this object. """
        return "Undefined. for <%s %s>" % (self.__class__.__name__, id(self))

    def __str__(self) -> str:
        return self.object_id()

    def __repr__(self) -> str:
        return '<%s>' % self.object_id()

    def __hash__(self) -> int:
        return hash(self.object_id())

    def __eq__(self, other) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        if other.object_id() == self.object_id():
            return True
        return False


class VppObjectRegistry(object):
    """ Class which handles automatic configuration cleanup. """
    _shared_state = {}

    def __init__(self) -> None:
        self.__dict__ = self._shared_state
        if not hasattr(self, "_object_registry"):
            self._object_registry = []
        if not hasattr(self, "_object_dict"):
            self._object_dict = dict()

    def register(self, obj: VppObject, logger) -> None:
        """ Register an object in the registry. """
        if obj.object_id() not in self._object_dict:
            self._object_registry.append(obj)
            self._object_dict[obj.object_id()] = obj
            logger.debug("REG: registering %s" % obj)
        else:
            logger.debug("REG: duplicate add, ignoring (%s)" % obj)

    def unregister(self, obj, logger) -> None:
        if obj.object_id() in self._object_dict:
            del self._object_dict[obj.object_id()]
            self._object_registry.remove(obj)
            logger.debug("REG: removing %s" % obj)
        else:
            logger.debug("REG: removing nonexistent (%r), ignoring" % obj)

    def unregister_all(self, logger):
        """ Remove all object registrations from registry. """
        logger.debug("REG: removing all object registrations")
        self._object_registry = []
        self._object_dict = dict()

    def remove_vpp_config(self, logger) -> None:
        """
        Remove configuration (if present) from vpp and then remove all objects
        from the registry.
        """
        if not self._object_registry:
            logger.info("REG: No objects registered for auto-cleanup.")
            return
        logger.info("REG: Removing VPP configuration for registered objects")
        # remove the config in reverse order as there might be dependencies
        failed = []
        for obj in reversed(self._object_registry):
            if obj.query_vpp_config():
                logger.info("REG: Removing configuration for %s" % obj)
                obj.remove_vpp_config()
                if obj.query_vpp_config():
                    failed.append(obj)
            else:
                logger.info(
                    "REG: Skipping removal for %s, configuration not present" %
                    obj)
        if failed:
            critical = False
            logger.error("REG: Couldn't remove configuration for object(s):")
            for obj in failed:
                logger.error(repr(obj))
                if not obj.ignore_removal_failure:
                    critical = True
            if critical:
                raise RuntimeError("Couldn't remove configuration for "
                                   "object(s): %s" %
                                   (", ".join(str(x) for x in failed)))

        self.unregister_all(logger)
