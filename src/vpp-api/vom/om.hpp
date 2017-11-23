/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __VOM_OM_H__
#define __VOM_OM_H__

#include <algorithm>
#include <memory>
#include <set>

#include "vom/client_db.hpp"
#include "vom/hw.hpp"

/**

The VPP Object Model (VOM) library.

Before we begin, a glossary of terms:
   - Agent or client: A user mode process that links to and uses the VOM library
     to programme VPP
   - VPP: A running instance of VPP
   - High Availability (HA): Scenarios where the client and/or VPP restart with
     minimal service interruption.
   - CReate, Update, Delete (CRUD): An API style where the producer issues
     notifications to changes to objects

The VOM is a C++ library that models entities in VPP as C++ classes. The
 relationships between VOM objects and VPP entities is not always 1:1. Some
 effort has been made to construct a higher level, more abstract API to VPP
 programming*.
The client programming model is simple (or at least I intended it to be..). The
client deals in ‘desired’ state, that is, it expresses the objects it wants to
exists (in VPP) and the properties that the object should have, i.e**;
    Interface af1(“my-af-packet-1”, AFPACKET, admin::UP);
Then the client ‘writes’ this object into the ‘model’
    OM::write(“clients-thing-1”, af1);

“clients-thing-1” is a description of the entity within the client’s domain that
‘owns’ (or has locked or has a reference to) the VOM object. There can be many
owners of each VOM object. It will be the last owner’s update that will be
programmed in VPP. This model means that the client is not burdened with
maintaining which of its objects have created which VOM objects. If the client
is itself driven by a CRUD API, then create notifications are implemented as
 above. Update notifications add two extra statements;
    OM::mark(“clients-thing-1”);
    … do writes ….
    OM::sweep(“clients-thing-1”);
These ‘mark’ and ‘sweep’ statements are indications to OM that firstly, indicate
that all the objects owned by “clients-thing-1” are now stale, i.e that the
client may no longer need them. If one of the subsequent writes should update a
stale object, then it is no longer stale. The sweep statement will ‘remove’ all
the remaining stale objects. In this model, the client does not need to maintain
the mapping of VOM objects to its own objects – it can simply express what it
needs now.
The delete notification is simply:
     OM::remove(“clients-thing-1”);
Which will remove all the objects in VOM that are owned by “clients-thing-1”.
Where ‘remove’ in this sense means unlock and unreference, the VOM object, and
VPP state, will only be truly removed once there are no more owners. This is
equivalent to a mark & sweep with no intermediate writes.

To provide this client side model the VOM is a stateful library, meaning that
for each entity it creates in VPP, VOM maintains its own representation of that
object. VOM can therefore be memory hungry. The desired state is expressed by
the client, the ‘actual’ state is maintained by VOM. VOM will consolidate the
two states when the client writes to the OM and thus issue VPP only the changes
required.

The concepts of ownership and statefulness also allow the support for HA
scenarios.
VPP restart: When VPP restarts, VOM will reconnect and ‘replay’ its state, in
dependency order, to VPP. The client does not need to regenerate its desired
state.
Client restart: when the client restarts, VOM will read/dump the current state
of all VPP objects and store them in the OM owned by the special owner “boot”.
As the client reprogrammes its desired state, objects will become owned by both
the boot process and the client. At the point in time, as determined by the
client, all stale state, that owned only by boot, can be purged. Hence the
system reaches the correct final state, with no interruption to VPP forwarding.


Basic Design:

Each object in VOM (i.e. an interface, route, bridge-domain, etc) is stored in a
per-type object database, with an object-type specific key. This ‘singular’ DB
has a value-type of a weak pointer to the object. I use the term ‘singular’ to
refer to the instance of the object stored in these databases, to be distinct
from the instances the client constructs to represent desired state.
The ‘client’ DB maintains the mapping of owner to object. The value type of the
client DB is a shared pointer to the singular instance of the owned object.
Once all the owners are gone, and all the shared pointers are destroyed, the
singular instance is also destroyed.

Each VOM object has some basic behaviour:
  update: issue to VPP an update to this object’s state. This could include the
          create
  sweep: delete the VPP entity – called when the object is destroyed.
  replay: issue to VPP all the commands needed to re-programme (VPP restart HA
          scenario)
  populate: read state from VPP and add it to the OM (client restart HA
scenario)

The object code is boiler-plate, in some cases (like the ACLs) even template.
The objects are purposefully left as simple, functionality free as possible.

Communication with VPP is through a ‘queue’ of ‘commands’. A command is
essentially an object wrapper around a VPP binary API call (although we do use
the VAPI C++ bindings too). Commands come in three flavours:
  RPC: do this; done.
  DUMP: give me all of these things; here you go
  EVENT; tell me about these events; here’s one …. Here’s one…. Oh here’s
         another….. etc.

RPC and DUMP commands are handled synchronously. Therefore on return from
OM::write(…) VPP has been issued with the request and responded. EVENTs are
asynchronous and will be delivered to the listeners in a different thread – so
beware!!

* As such VOM provides some level of insulation to the changes to the VPP
  binary API.
** some of the type names are shorten for brevity’s sake.

*/
namespace VOM {
/**
 * The interface to writing objects into VPP OM.
 */
class OM
{
public:
  /**
   * A class providing the RAII pattern for mark and sweep
   */
  class mark_n_sweep
  {
  public:
    /**
     * Constructor - will call mark on the key
     */
    mark_n_sweep(const client_db::key_t& key);

    /**
     * Destructor - will call sweep on the key
     */
    ~mark_n_sweep();

  private:
    /**
     * no copies
     */
    mark_n_sweep(const mark_n_sweep& ms) = delete;

    /**
     * The client whose state we are guarding.
     */
    client_db::key_t m_key;
  };

  /**
   * Init
   */
  static void init();

  /**
   * populate the OM with state read from HW.
   */
  static void populate(const client_db::key_t& key);

  /**
   * Mark all state owned by this key as stale
   */
  static void mark(const client_db::key_t& key);

  /**
   * Sweep all the key's objects that are stale
   */
  static void sweep(const client_db::key_t& key);

  /**
   * Replay all of the objects to HW.
   */
  static void replay(void);

  /**
   * Make the State in VPP reflect the expressed desired state.
   *  But don't call the HW - use this whilst processing dumped
   *  data from HW
   */
  template <typename OBJ>
  static rc_t commit(const client_db::key_t& key, const OBJ& obj)
  {
    rc_t rc = rc_t::OK;

    HW::disable();
    rc = OM::write(key, obj);
    HW::enable();

    return (rc);
  }

  /**
   * Make the State in VPP reflect the expressed desired state.
   *  After processing all the objects in the queue, in FIFO order,
   *  any remaining state owned by the client_db::key_t is purged.
   * This is a template function so the object's update() function is
   * always called with the derived type.
   */
  template <typename OBJ>
  static rc_t write(const client_db::key_t& key, const OBJ& obj)
  {
    rc_t rc = rc_t::OK;

    /*
     * Find the singular instance another owner may have created.
     * this always returns something.
     */
    std::shared_ptr<OBJ> inst = obj.singular();

    /*
     * Update the existing object with the new desired state
     */
    inst->update(obj);

    /*
     * Find if the object already stored on behalf of this key.
     * and mark them stale
     */
    object_ref_list& objs = m_db->find(key);

    /*
     * Iterate through this list to find a matchin' object
     * to the one requested.
     */
    auto match_ptr = [inst](const object_ref& oref) {
      return (inst == oref.obj());
    };
    auto it = std::find_if(objs.begin(), objs.end(), match_ptr);

    if (it != objs.end()) {
      /*
       * yes, this key already owns this object.
       */
      it->clear();
    } else {
      /*
       * Add the singular instance to the owners list
       */
      objs.insert(object_ref(inst));
    }

    return (HW::write());
  }

  /**
   * Remove all object in the OM referenced by the key
   */
  static void remove(const client_db::key_t& key);

  /**
   * Print each of the object in the DB into the stream provided
   */
  static void dump(const client_db::key_t& key, std::ostream& os);

  /**
   * Print each of the KEYS
   */
  static void dump(std::ostream& os);

  /**
   * Class definition for listeners to OM events
   */
  class listener
  {
  public:
    listener() = default;
    virtual ~listener() = default;

    /**
     * Handle a populate event
     */
    virtual void handle_populate(const client_db::key_t& key) = 0;

    /**
     * Handle a replay event
     */
    virtual void handle_replay() = 0;

    /**
     * Get the sortable Id of the listener
     */
    virtual dependency_t order() const = 0;

    /**
     * less than operator for set sorting
     */
    bool operator<(const listener& listener) const
    {
      return (order() < listener.order());
    }
  };

  /**
   * Register a listener of events
   */
  static bool register_listener(listener* listener);

private:
  /**
   * Database of object state created for each key
   */
  static client_db* m_db;

  /**
   * Comparator to keep the pointers to listeners in sorted order
   */
  struct listener_comparator_t
  {
    bool operator()(const listener* l1, const listener* l2) const
    {
      return (l1->order() < l2->order());
    }
  };

  /**
   * convenient typedef for the sorted set of listeners
   */
  typedef std::multiset<listener*, listener_comparator_t> listener_list;

  /**
   * The listeners for events
   */
  static std::unique_ptr<listener_list> m_listeners;
};
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */

#endif
