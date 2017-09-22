/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#ifndef vapi_hpp_included
#define vapi_hpp_included

#include <cstddef>
#include <vector>
#include <mutex>
#include <queue>
#include <cassert>
#include <functional>
#include <algorithm>
#include <atomic>
#include <vppinfra/types.h>
#include <vapi/vapi.h>
#include <vapi/vapi_internal.h>
#include <vapi/vapi_dbg.h>
#include <vapi/vpe.api.vapi.h>

#if VAPI_CPP_DEBUG_LEAKS
#include <unordered_set>
#endif

/**
 * @file
 * @brief C++ VPP API
 */

namespace vapi
{

class Connection;

template <typename Req, typename Resp, typename... Args> class Request;
template <typename M> class Msg;
template <typename M> void vapi_swap_to_be (M *msg);
template <typename M> void vapi_swap_to_host (M *msg);
template <typename M, typename... Args>
M *vapi_alloc (Connection &con, Args...);
template <typename M> vapi_msg_id_t vapi_get_msg_id_t ();
template <typename M> class Event_registration;

class Unexpected_msg_id_exception : public std::exception
{
public:
  virtual const char *what () const throw ()
  {
    return "unexpected message id";
  }
};

class Msg_not_available_exception : public std::exception
{
public:
  virtual const char *what () const throw ()
  {
    return "message unavailable";
  }
};

typedef enum {
  /** response not ready yet */
  RESPONSE_NOT_READY,

  /** response to request is ready */
  RESPONSE_READY,

  /** no response to request (will never come) */
  RESPONSE_NO_RESPONSE,
} vapi_response_state_e;

/**
 * Class representing common functionality of a request - response state
 * and context
 */
class Common_req
{
public:
  virtual ~Common_req (){};

  Connection &get_connection ()
  {
    return con;
  };

  vapi_response_state_e get_response_state (void) const
  {
    return response_state;
  }

private:
  Connection &con;
  Common_req (Connection &con) : con{con}, response_state{RESPONSE_NOT_READY}
  {
  }

  void set_response_state (vapi_response_state_e state)
  {
    response_state = state;
  }

  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data) = 0;

  void set_context (u32 context)
  {
    this->context = context;
  }

  u32 get_context ()
  {
    return context;
  }

  u32 context;
  vapi_response_state_e response_state;

  friend class Connection;

  template <typename M> friend class Msg;

  template <typename Req, typename Resp, typename... Args>
  friend class Request;

  template <typename Req, typename Resp, typename... Args> friend class Dump;

  template <typename M> friend class Event_registration;
};

/**
 * Class representing a connection to VPP
 *
 * After creating a Connection object, call connect() to actually connect
 * to VPP. Use is_msg_available to discover whether a specific message is known
 * and supported by the VPP connected to.
 */
class Connection
{
public:
  Connection (void) : vapi_ctx{0}, event_count{0}
  {

    vapi_error_e rv = VAPI_OK;
    if (!vapi_ctx)
      {
        if (VAPI_OK != (rv = vapi_ctx_alloc (&vapi_ctx)))
          {
            throw std::bad_alloc ();
          }
      }
    events.reserve (vapi_get_message_count () + 1);
  }

  Connection (const Connection &) = delete;

  ~Connection (void)
  {
    vapi_ctx_free (vapi_ctx);
#if VAPI_CPP_DEBUG_LEAKS
    for (auto x : shm_data_set)
      {
        printf ("Leaked shm_data@%p!\n", x);
      }
#endif
  }

  /**
   * @brief check if message identified by it's message id is known by the
   * vpp to which the connection is open
   */
  bool is_msg_available (vapi_msg_id_t type)
  {
    return vapi_is_msg_available (vapi_ctx, type);
  }

  /**
   * @brief connect to vpp
   *
   * @param name application name
   * @param chroot_prefix shared memory prefix
   * @param max_queued_request max number of outstanding requests queued
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e connect (const char *name, const char *chroot_prefix,
                        int max_outstanding_requests, int response_queue_size)
  {
    return vapi_connect (vapi_ctx, name, chroot_prefix,
                         max_outstanding_requests, response_queue_size,
                         VAPI_MODE_BLOCKING);
  }

  /**
   * @brief disconnect from vpp
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e disconnect ()
  {
    auto x = requests.size ();
    while (x > 0)
      {
        VAPI_DBG ("popping request @%p", requests.front ());
        requests.pop_front ();
        --x;
      }
    return vapi_disconnect (vapi_ctx);
  };

  /**
   * @brief get event file descriptor
   *
   * @note this file descriptor becomes readable when messages (from vpp)
   * are waiting in queue
   *
   * @param[out] fd pointer to result variable
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e get_fd (int *fd)
  {
    return vapi_get_fd (vapi_ctx, fd);
  }

  /**
   * @brief wait for responses from vpp and assign them to appropriate objects
   *
   * @param limit stop dispatch after the limit object received it's response
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e dispatch (const Common_req *limit = nullptr)
  {
    std::lock_guard<std::mutex> lock (dispatch_mutex);
    vapi_error_e rv = VAPI_OK;
    bool loop_again = true;
    while (loop_again)
      {
        void *shm_data;
        size_t shm_data_size;
        rv = vapi_recv (vapi_ctx, &shm_data, &shm_data_size);
        if (VAPI_OK != rv)
          {
            return rv;
          }
#if VAPI_CPP_DEBUG_LEAKS
        on_shm_data_alloc (shm_data);
#endif
        std::lock_guard<std::recursive_mutex> requests_lock (requests_mutex);
        std::lock_guard<std::recursive_mutex> events_lock (events_mutex);
        vapi_msg_id_t id = vapi_lookup_vapi_msg_id_t (
            vapi_ctx, be16toh (*static_cast<u16 *> (shm_data)));
        bool has_context = vapi_msg_is_with_context (id);
        bool break_dispatch = false;
        Common_req *matching_req = nullptr;
        if (has_context)
          {
            u32 context = *reinterpret_cast<u32 *> (
                (static_cast<u8 *> (shm_data) + vapi_get_context_offset (id)));
            const auto x = requests.front ();
            matching_req = x;
            if (context == x->context)
              {
                std::tie (rv, break_dispatch) =
                    x->assign_response (id, shm_data);
              }
            else
              {
                std::tie (rv, break_dispatch) =
                    x->assign_response (id, nullptr);
              }
            if (break_dispatch)
              {
                requests.pop_front ();
              }
          }
        else
          {
            if (events[id])
              {
                std::tie (rv, break_dispatch) =
                    events[id]->assign_response (id, shm_data);
                matching_req = events[id];
              }
            else
              {
                msg_free (shm_data);
              }
          }
        if ((matching_req && matching_req == limit && break_dispatch) ||
            VAPI_OK != rv)
          {
            return rv;
          }
        loop_again = !requests.empty () || (event_count > 0);
      }
    return rv;
  }

  /**
   * @brief convenience wrapper function
   */
  vapi_error_e dispatch (const Common_req &limit)
  {
    return dispatch (&limit);
  }

  /**
   * @brief wait for response to a specific request
   *
   * @param req request to wait for response for
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e wait_for_response (const Common_req &req)
  {
    if (RESPONSE_READY == req.get_response_state ())
      {
        return VAPI_OK;
      }
    return dispatch (req);
  }

private:
  void msg_free (void *shm_data)
  {
#if VAPI_CPP_DEBUG_LEAKS
    on_shm_data_free (shm_data);
#endif
    vapi_msg_free (vapi_ctx, shm_data);
  }

  template <template <typename XReq, typename XResp, typename... XArgs>
            class X,
            typename Req, typename Resp, typename... Args>
  vapi_error_e send (X<Req, Resp, Args...> *req)
  {
    if (!req)
      {
        return VAPI_EINVAL;
      }
    u32 req_context =
        req_context_counter.fetch_add (1, std::memory_order_relaxed);
    req->request.shm_data->header.context = req_context;
    vapi_swap_to_be<Req> (req->request.shm_data);
    std::lock_guard<std::recursive_mutex> lock (requests_mutex);
    vapi_error_e rv = vapi_send (vapi_ctx, req->request.shm_data);
    if (VAPI_OK == rv)
      {
        VAPI_DBG ("Push %p", req);
        requests.emplace_back (req);
        req->set_context (req_context);
#if VAPI_CPP_DEBUG_LEAKS
        on_shm_data_free (req->request.shm_data);
#endif
        req->request.shm_data = nullptr; /* consumed by vapi_send */
      }
    else
      {
        vapi_swap_to_host<Req> (req->request.shm_data);
      }
    return rv;
  }

  template <template <typename XReq, typename XResp, typename... XArgs>
            class X,
            typename Req, typename Resp, typename... Args>
  vapi_error_e send_with_control_ping (X<Req, Resp, Args...> *req)
  {
    if (!req)
      {
        return VAPI_EINVAL;
      }
    u32 req_context =
        req_context_counter.fetch_add (1, std::memory_order_relaxed);
    req->request.shm_data->header.context = req_context;
    vapi_swap_to_be<Req> (req->request.shm_data);
    std::lock_guard<std::recursive_mutex> lock (requests_mutex);
    vapi_error_e rv = vapi_send_with_control_ping (
        vapi_ctx, req->request.shm_data, req_context);
    if (VAPI_OK == rv)
      {
        VAPI_DBG ("Push %p", req);
        requests.emplace_back (req);
        req->set_context (req_context);
#if VAPI_CPP_DEBUG_LEAKS
        on_shm_data_free (req->request.shm_data);
#endif
        req->request.shm_data = nullptr; /* consumed by vapi_send */
      }
    else
      {
        vapi_swap_to_host<Req> (req->request.shm_data);
      }
    return rv;
  }

  void unregister_request (Common_req *request)
  {
    std::lock_guard<std::recursive_mutex> lock (requests_mutex);
    std::remove (requests.begin (), requests.end (), request);
  }

  template <typename M> void register_event (Event_registration<M> *event)
  {
    const vapi_msg_id_t id = M::get_msg_id ();
    std::lock_guard<std::recursive_mutex> lock (events_mutex);
    events[id] = event;
    ++event_count;
  }

  template <typename M> void unregister_event (Event_registration<M> *event)
  {
    const vapi_msg_id_t id = M::get_msg_id ();
    std::lock_guard<std::recursive_mutex> lock (events_mutex);
    events[id] = nullptr;
    --event_count;
  }

  vapi_ctx_t vapi_ctx;
  std::atomic_ulong req_context_counter;
  std::mutex dispatch_mutex;

  std::recursive_mutex requests_mutex;
  std::recursive_mutex events_mutex;
  std::deque<Common_req *> requests;
  std::vector<Common_req *> events;
  int event_count;

  template <typename Req, typename Resp, typename... Args>
  friend class Request;

  template <typename Req, typename Resp, typename... Args> friend class Dump;

  template <typename M> friend class Result_set;

  template <typename M> friend class Event_registration;

  template <typename M, typename... Args>
  friend M *vapi_alloc (Connection &con, Args...);

  template <typename M> friend class Msg;

#if VAPI_CPP_DEBUG_LEAKS
  void on_shm_data_alloc (void *shm_data)
  {
    if (shm_data)
      {
        auto pos = shm_data_set.find (shm_data);
        if (pos == shm_data_set.end ())
          {
            shm_data_set.insert (shm_data);
          }
        else
          {
            printf ("Double-add shm_data @%p!\n", shm_data);
          }
      }
  }

  void on_shm_data_free (void *shm_data)
  {
    auto pos = shm_data_set.find (shm_data);
    if (pos == shm_data_set.end ())
      {
        printf ("Freeing untracked shm_data @%p!\n", shm_data);
      }
    else
      {
        shm_data_set.erase (pos);
      }
  }
  std::unordered_set<void *> shm_data_set;
#endif
};

template <typename Req, typename Resp, typename... Args> class Request;

template <typename Req, typename Resp, typename... Args> class Dump;

template <class, class = void> struct vapi_has_payload_trait : std::false_type
{
};

template <class... T> using vapi_void_t = void;

template <class T>
struct vapi_has_payload_trait<T, vapi_void_t<decltype (&T::payload)>>
    : std::true_type
{
};

template <typename M> void vapi_msg_set_msg_id (vapi_msg_id_t id)
{
  Msg<M>::set_msg_id (id);
}

/**
 * Class representing a message stored in shared memory
 */
template <typename M> class Msg
{
public:
  Msg (const Msg &) = delete;

  ~Msg ()
  {
    VAPI_DBG ("Destroy Msg<%s>@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), this, shm_data);
    if (shm_data)
      {
        con.get ().msg_free (shm_data);
        shm_data = nullptr;
      }
  }

  static vapi_msg_id_t get_msg_id ()
  {
    return *msg_id_holder ();
  }

  template <typename X = M>
  typename std::enable_if<vapi_has_payload_trait<X>::value,
                          decltype (X::payload) &>::type
  get_payload () const
  {
    return shm_data->payload;
  }

private:
  Msg (Msg<M> &&msg) : con{msg.con}
  {
    VAPI_DBG ("Move construct Msg<%s> from msg@%p to msg@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), &msg, this, msg.shm_data);
    shm_data = msg.shm_data;
    msg.shm_data = nullptr;
  }

  Msg<M> &operator= (Msg<M> &&msg)
  {
    VAPI_DBG ("Move assign Msg<%s> from msg@%p to msg@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), &msg, this, msg.shm_data);
    con.get ().msg_free (shm_data);
    con = msg.con;
    shm_data = msg.shm_data;
    msg.shm_data = nullptr;
    return *this;
  }

  struct Msg_allocator : std::allocator<Msg<M>>
  {
    template <class U, class... Args> void construct (U *p, Args &&... args)
    {
      ::new ((void *)p) U (std::forward<Args> (args)...);
    }

    template <class U> struct rebind
    {
      typedef Msg_allocator other;
    };
  };

  static void set_msg_id (vapi_msg_id_t id)
  {
    assert ((~0 == *msg_id_holder ()) || (id == *msg_id_holder ()));
    *msg_id_holder () = id;
  }

  static vapi_msg_id_t *msg_id_holder ()
  {
    static vapi_msg_id_t my_id{~0};
    return &my_id;
  }

  Msg (Connection &con, void *shm_data) : con{con}
  {
    if (!con.is_msg_available (get_msg_id ()))
      {
        throw Msg_not_available_exception ();
      }
    this->shm_data = static_cast<shm_data_type *> (shm_data);
    VAPI_DBG ("New Msg<%s>@%p shm_data@%p", vapi_get_msg_name (get_msg_id ()),
              this, shm_data);
  }

  void assign_response (vapi_msg_id_t resp_id, void *shm_data)
  {
    assert (nullptr == this->shm_data);
    if (resp_id != get_msg_id ())
      {
        throw Unexpected_msg_id_exception ();
      }
    this->shm_data = static_cast<M *> (shm_data);
    vapi_swap_to_host<M> (this->shm_data);
    VAPI_DBG ("Assign response to Msg<%s>@%p shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), this, shm_data);
  }

  std::reference_wrapper<Connection> con;
  using shm_data_type = M;
  shm_data_type *shm_data;

  friend class Connection;

  template <typename Req, typename Resp, typename... Args>
  friend class Request;

  template <typename Req, typename Resp, typename... Args> friend class Dump;

  template <typename X> friend class Event_registration;

  template <typename X> friend class Result_set;

  friend struct Msg_allocator;

  template <typename X> friend void vapi_msg_set_msg_id (vapi_msg_id_t id);
};

/**
 * Class representing a simple request - with a single response message
 */
template <typename Req, typename Resp, typename... Args>
class Request : public Common_req
{
public:
  Request (Connection &con, Args... args,
           std::function<vapi_error_e (Request<Req, Resp, Args...> &)>
               callback = nullptr)
      : Common_req{con}, callback{callback},
        request{con, vapi_alloc<Req> (con, args...)}, response{con, nullptr}
  {
  }

  Request (const Request &) = delete;

  virtual ~Request ()
  {
    if (RESPONSE_NOT_READY == get_response_state ())
      {
        con.unregister_request (this);
      }
  }

  vapi_error_e execute ()
  {
    return con.send (this);
  }

  const Msg<Req> &get_request (void) const
  {
    return request;
  }

  const Msg<Resp> &get_response (void)
  {
    return response;
  }

private:
  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    assert (RESPONSE_NOT_READY == get_response_state ());
    response.assign_response (id, shm_data);
    set_response_state (RESPONSE_READY);
    if (nullptr != callback)
      {
        return std::make_pair (callback (*this), true);
      }
    return std::make_pair (VAPI_OK, true);
  }
  std::function<vapi_error_e (Request<Req, Resp, Args...> &)> callback;
  Msg<Req> request;
  Msg<Resp> response;

  friend class Connection;
};

/**
 * Class representing iterable set of responses of the same type
 */
template <typename M> class Result_set
{
public:
  ~Result_set ()
  {
  }

  Result_set (const Result_set &) = delete;

  bool is_complete () const
  {
    return complete;
  }

  size_t size () const
  {
    return set.size ();
  }

  using const_iterator =
      typename std::vector<Msg<M>,
                           typename Msg<M>::Msg_allocator>::const_iterator;

  const_iterator begin () const
  {
    return set.begin ();
  }

  const_iterator end () const
  {
    return set.end ();
  }

  void free_response (const_iterator pos)
  {
    set.erase (pos);
  }

  void free_all_responses ()
  {
    set.clear ();
  }

private:
  void mark_complete ()
  {
    complete = true;
  }

  void assign_response (vapi_msg_id_t resp_id, void *shm_data)
  {
    if (resp_id != Msg<M>::get_msg_id ())
      {
        {
          throw Unexpected_msg_id_exception ();
        }
      }
    else if (shm_data)
      {
        vapi_swap_to_host<M> (static_cast<M *> (shm_data));
        set.emplace_back (con, shm_data);
        VAPI_DBG ("Result_set@%p emplace_back shm_data@%p", this, shm_data);
      }
  }

  Result_set (Connection &con) : con{con}, complete{false}
  {
  }

  Connection &con;
  bool complete;
  std::vector<Msg<M>, typename Msg<M>::Msg_allocator> set;

  template <typename Req, typename Resp, typename... Args> friend class Dump;

  template <typename X> friend class Event_registration;
};

/**
 * Class representing a dump request - zero or more identical responses to a
 * single request message
 */
template <typename Req, typename Resp, typename... Args>
class Dump : public Common_req
{
public:
  Dump (Connection &con, Args... args,
        std::function<vapi_error_e (Dump<Req, Resp, Args...> &)> callback =
            nullptr)
      : Common_req{con}, request{con, vapi_alloc<Req> (con, args...)},
        result_set{con}, callback{callback}
  {
  }

  Dump (const Dump &) = delete;

  virtual ~Dump ()
  {
  }

  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    if (id == vapi_msg_id_control_ping_reply)
      {
        con.msg_free (shm_data);
        result_set.mark_complete ();
        set_response_state (RESPONSE_READY);
        if (nullptr != callback)
          {
            return std::make_pair (callback (*this), true);
          }
        return std::make_pair (VAPI_OK, true);
      }
    else
      {
        result_set.assign_response (id, shm_data);
      }
    return std::make_pair (VAPI_OK, false);
  }

  vapi_error_e execute ()
  {
    return con.send_with_control_ping (this);
  }

  Msg<Req> &get_request (void)
  {
    return request;
  }

  using resp_type = typename Msg<Resp>::shm_data_type;

  const Result_set<Resp> &get_result_set (void) const
  {
    return result_set;
  }

private:
  Msg<Req> request;
  Result_set<resp_type> result_set;
  std::function<vapi_error_e (Dump<Req, Resp, Args...> &)> callback;

  friend class Connection;
};

/**
 * Class representing event registration - incoming events (messages) from
 * vpp as a result of a subscription (typically a want_* simple request)
 */
template <typename M> class Event_registration : public Common_req
{
public:
  Event_registration (
      Connection &con,
      std::function<vapi_error_e (Event_registration<M> &)> callback = nullptr)
      : Common_req{con}, result_set{con}, callback{callback}
  {
    if (!con.is_msg_available (M::get_msg_id ()))
      {
        throw Msg_not_available_exception ();
      }
    con.register_event (this);
  }

  Event_registration (const Event_registration &) = delete;

  virtual ~Event_registration ()
  {
    con.unregister_event (this);
  }

  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    result_set.assign_response (id, shm_data);
    if (nullptr != callback)
      {
        return std::make_pair (callback (*this), true);
      }
    return std::make_pair (VAPI_OK, true);
  }

  using resp_type = typename M::shm_data_type;

  Result_set<resp_type> &get_result_set (void)
  {
    return result_set;
  }

private:
  Result_set<resp_type> result_set;
  std::function<vapi_error_e (Event_registration<M> &)> callback;
};
};

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
