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
#include <vapi.h>
#include <vapi_internal.h>
#include <vapi_dbg.h>
#include <vpe.api.vapi.h>

#if VAPI_CPP_DEBUG_LEAKS
#include <unordered_set>
#endif

namespace vapi
{

class Vapi_connection;

template <typename Req, typename Resp, typename... Args> class Vapi_req;
template <typename Msg> class Vapi_msg;
template <typename Msg> void vapi_swap_to_be (Msg *msg);
template <typename Msg> void vapi_swap_to_host (Msg *msg);
template <typename Msg, typename... Args>
Msg *vapi_alloc (Vapi_connection *con, Args...);
template <typename Msg> vapi_msg_id_t vapi_get_msg_id_t ();
template <typename Vapi_msg_resp> class Vapi_event_registration;

class Vapi_unexpected_msg_id_exception : public std::exception
{
public:
  virtual const char *what () const throw ()
  {
    return "unexpected message id";
  }
};

class Vapi_msg_not_available_exception : public std::exception
{
public:
  virtual const char *what () const throw () { return "message unavailable"; }
};

typedef enum {
  /** response not ready yet */
  RESPONSE_NOT_READY,
  /** response to request is ready */
  RESPONSE_READY,
  /** no response to request (will never come) */
  RESPONSE_NO_RESPONSE,
} vapi_response_state_e;

class Vapi_common_req
{
public:
  virtual ~Vapi_common_req (){};
  Vapi_connection *get_connection () { return con; };
  vapi_response_state_e get_response_state (void) const
  {
    return response_state;
  }

private:
  friend class Vapi_connection;
  template <typename Msg> friend class Vapi_msg;
  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_req;
  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_dump;
  template <typename Vapi_msg_resp> friend class Vapi_event_registration;
  Vapi_connection *con;
  Vapi_common_req (Vapi_connection *con)
      : con{con}, response_state{RESPONSE_NOT_READY}
  {
  }
  void set_response_state (vapi_response_state_e state)
  {
    response_state = state;
  }
  vapi_response_state_e response_state;
  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data) = 0;
  void set_context (u32 context) { this->context = context; }
  u32 get_context () { return context; }
  u32 context;
};

class Vapi_connection
{
public:
  /**
   * @brief allocate vapi context
   *
   * @return VAPI_OK on success, other error code on error
   */
  Vapi_connection (void) : event_count{0}
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

  /**
   * @brief free vapi context
   */
  ~Vapi_connection (void)
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
   * @param ctx opaque vapi context
   * @param[out] fd pointer to result variable
   *
   * @return VAPI_OK on success, other error code on error
   */
  vapi_error_e get_fd (int *fd);

  vapi_error_e dispatch (const Vapi_common_req *limit = nullptr)
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
        Vapi_common_req *matching_req = nullptr;
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

  vapi_error_e dispatch (const Vapi_common_req &limit)
  {
    return dispatch (&limit);
  }

  vapi_error_e wait_for_response (const Vapi_common_req &req)
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

  void read_internal () {}

  template <typename Msg> friend class Vapi_msg;

  template <template <typename XReq, typename XResp, typename... XArgs>
            class X,
            typename Req, typename Resp, typename... Args>
  vapi_error_e send (X<Req, Resp, Args...> *req)
  {
    u32 req_context =
        req_context_counter.fetch_add (1, std::memory_order_relaxed);
    req->request.shm_data->header.context = req_context;
    vapi_swap_to_be<Req> (req->request.shm_data);
    vapi_error_e rv = vapi_send (vapi_ctx, req->request.shm_data);
    if (VAPI_OK == rv)
      {
        VAPI_DBG ("Push %p", req);
        std::lock_guard<std::recursive_mutex> lock (requests_mutex);
        requests.emplace_back (req);
        req->set_context (req_context);
#if VAPI_CPP_DEBUG_LEAKS
        on_shm_data_free (req->request.shm_data);
#endif
        req->request.shm_data = nullptr; /* consumed by vapi_send */
      }
    return rv;
  }

  template <template <typename XReq, typename XResp, typename... XArgs>
            class X,
            typename Req, typename Resp, typename... Args>
  vapi_error_e send_with_control_ping (X<Req, Resp, Args...> *req)
  {
    u32 req_context =
        req_context_counter.fetch_add (1, std::memory_order_relaxed);
    req->request.shm_data->header.context = req_context;
    vapi_swap_to_be<Req> (req->request.shm_data);
    vapi_error_e rv = vapi_send_with_control_ping (
        vapi_ctx, req->request.shm_data, req_context);
    if (VAPI_OK == rv)
      {
        VAPI_DBG ("Push %p", req);
        std::lock_guard<std::recursive_mutex> lock (requests_mutex);
        requests.emplace_back (req);
        req->set_context (req_context);
#if VAPI_CPP_DEBUG_LEAKS
        on_shm_data_free (req->request.shm_data);
#endif
        req->request.shm_data = nullptr; /* consumed by vapi_send */
      }
    return rv;
  }

  void unregister_request (Vapi_common_req *request)
  {
    std::lock_guard<std::recursive_mutex> lock (requests_mutex);
    std::remove (requests.begin (), requests.end (), request);
  }

  template <typename Vapi_msg_resp>
  void register_event (Vapi_event_registration<Vapi_msg_resp> *event)
  {
    const vapi_msg_id_t id = Vapi_msg_resp::get_msg_id ();
    std::lock_guard<std::recursive_mutex> lock (events_mutex);
    events[id] = event;
    ++event_count;
  }

  template <typename Vapi_msg_resp>
  void unregister_event (Vapi_event_registration<Vapi_msg_resp> *event)
  {
    const vapi_msg_id_t id = Vapi_msg_resp::get_msg_id ();
    std::lock_guard<std::recursive_mutex> lock (events_mutex);
    events[id] = nullptr;
    --event_count;
  }

  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_req;

  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_dump;

  template <typename Msg> friend class Vapi_result_set;

  template <typename Vapi_msg_resp> friend class Vapi_event_registration;

  template <typename Msg, typename... Args>
  friend Msg *vapi_alloc (Vapi_connection *con, Args...);

  vapi_ctx_t vapi_ctx;
  std::atomic_ulong req_context_counter;
  std::recursive_mutex requests_mutex;
  std::recursive_mutex events_mutex;
  std::mutex dispatch_mutex;

  std::deque<Vapi_common_req *> requests;
  std::vector<Vapi_common_req *> events;
  int event_count;
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

template <typename Req, typename Resp, typename... Args> class Vapi_req;
template <typename Req, typename Resp, typename... Args> class Vapi_dump;

template <class, class = void> struct vapi_has_payload_trait : std::false_type
{
};

template <class... T> using vapi_void_t = void;

template <class T>
struct vapi_has_payload_trait<T, vapi_void_t<decltype (&T::payload)>>
    : std::true_type
{
};

template <typename Msg> void vapi_msg_set_msg_id (vapi_msg_id_t id)
{
  Vapi_msg<Msg>::set_msg_id (id);
}

class Vapi_common_msg
{
public:
  virtual ~Vapi_common_msg (){};
};

template <typename Msg> class Vapi_msg : Vapi_common_msg
{
  friend class Vapi_connection;

  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_req;

  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_dump;

  template <typename Vapi_msg_resp> friend class Vapi_event_registration;

  template <typename X> friend class Vapi_result_set;

  template <typename X> friend void vapi_msg_set_msg_id ();

public:
  ~Vapi_msg ()
  {
    VAPI_DBG ("Destroy Vapi_msg<%s>@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), this, shm_data);
    if (shm_data)
      {
        con->msg_free (shm_data);
        shm_data = nullptr;
      }
  }

  static vapi_msg_id_t get_msg_id () { return *msg_id_holder (); }

  template <typename X = Msg>
  typename std::enable_if<vapi_has_payload_trait<X>::value,
                          decltype (X::payload) *>::type
  get_payload () const
  {
    return &shm_data->payload;
  }

private:
  Vapi_msg (Vapi_msg<Msg> &&msg)
  {
    VAPI_DBG ("Move construct Vapi_msg<%s> from msg@%p to msg@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), &msg, this, msg.shm_data);
    con = msg.con;
    shm_data = msg.shm_data;
    msg.shm_data = nullptr;
  }

  Vapi_msg<Msg> &operator= (Vapi_msg<Msg> &&msg)
  {
    VAPI_DBG ("Move assign Vapi_msg<%s> from msg@%p to msg@%p, shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), &msg, this, msg.shm_data);
    con->msg_free (shm_data);
    con = msg.con;
    shm_data = msg.shm_data;
    msg.shm_data = nullptr;
    return *this;
  }

  struct Vapi_msg_allocator : std::allocator<Vapi_msg<Msg>>
  {
    template <class U, class... Args> void construct (U *p, Args &&... args)
    {
      ::new ((void *)p) U (std::forward<Args> (args)...);
    }

    template <class U> struct rebind
    {
      typedef Vapi_msg_allocator other;
    };
  };

  friend struct Vapi_msg_allocator;

  template <typename X> friend void vapi_msg_set_msg_id (vapi_msg_id_t id);

  static void set_msg_id (vapi_msg_id_t id)
  {
    assert (~0 == *msg_id_holder ());
    *msg_id_holder () = id;
  }

  static vapi_msg_id_t *msg_id_holder ()
  {
    static vapi_msg_id_t my_id{~0};
    return &my_id;
  }

  Vapi_msg (Vapi_connection *con,
            void *shm_data) throw (Vapi_msg_not_available_exception)
      : con{con}
  {
    if (!con->is_msg_available (get_msg_id ()))
      {
        throw Vapi_msg_not_available_exception ();
      }
    this->shm_data = static_cast<Msg *> (shm_data);
    VAPI_DBG ("New Vapi_msg<%s>@%p shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), this, shm_data);
  }

  void
  assign_response (vapi_msg_id_t resp_id,
                   void *shm_data) throw (Vapi_unexpected_msg_id_exception)
  {
    assert (nullptr == this->shm_data);
    if (resp_id != get_msg_id ())
      {
        throw Vapi_unexpected_msg_id_exception ();
      }
    this->shm_data = static_cast<Msg *> (shm_data);
    vapi_swap_to_host<Msg> (this->shm_data);
    VAPI_DBG ("Assign response to Vapi_msg<%s>@%p shm_data@%p",
              vapi_get_msg_name (get_msg_id ()), this, shm_data);
  }

  Vapi_connection *con;
  using shm_data_type = Msg;
  Msg *shm_data;
};

template <typename Req, typename Resp, typename... Args>
class Vapi_req : public Vapi_common_req
{
  friend class Vapi_connection;

public:
  Vapi_req (Vapi_connection *con, Args... args,
            std::function<vapi_error_e (Vapi_req<Req, Resp, Args...> *)>
                callback = nullptr)
      : Vapi_common_req{con}, callback{callback},
        request{con, vapi_alloc<Req> (con, args...)}, response{con, nullptr}
  {
  }

  virtual ~Vapi_req ()
  {
    if (RESPONSE_NOT_READY == get_response_state ())
      {
        con->unregister_request (this);
      }
  }

  vapi_error_e execute () { return con->send (this); }

  const Vapi_msg<Req> *get_request (void) const { return &request; }

  const Vapi_msg<Resp> *get_response (void) { return &response; }

private:
  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    assert (RESPONSE_NOT_READY == get_response_state ());
    response.assign_response (id, shm_data);
    set_response_state (RESPONSE_READY);
    if (nullptr != callback)
      {
        return std::make_pair (callback (this), true);
      }
    return std::make_pair (VAPI_OK, true);
  }
  std::function<vapi_error_e (Vapi_req<Req, Resp, Args...> *)> callback;
  Vapi_msg<Req> request;
  Vapi_msg<Resp> response;
};

template <typename Msg> class Vapi_result_set
{
  template <typename Req, typename Resp, typename... Args>
  friend class Vapi_dump;

  template <typename Vapi_msg_resp> friend class Vapi_event_registration;

public:
  ~Vapi_result_set () {}

  bool is_complete () const { return complete; }

  size_t size () const { return set.size (); }

  using const_iterator = typename std::vector<
      Vapi_msg<Msg>,
      typename Vapi_msg<Msg>::Vapi_msg_allocator>::const_iterator;

  const_iterator begin () const { return set.begin (); }

  const_iterator end () const { return set.end (); }

  void free_response (const_iterator pos) { set.erase (pos); }

  void free_all_responses () { set.clear (); }

private:
  void mark_complete () { complete = true; }

  void
  assign_response (vapi_msg_id_t resp_id,
                   void *shm_data) throw (Vapi_unexpected_msg_id_exception)
  {
    if (resp_id != Vapi_msg<Msg>::get_msg_id ())
      {
        {
          throw Vapi_unexpected_msg_id_exception ();
        }
      }
    else if (shm_data)
      {
        vapi_swap_to_host<Msg> (static_cast<Msg *> (shm_data));
        set.emplace_back (con, shm_data);
        VAPI_DBG ("Vapi_result_set@%p emplace_back shm_data@%p", this,
                  shm_data);
      }
  }

  Vapi_result_set (Vapi_connection *con) : con{con}, complete{false} {}
  Vapi_connection *con;
  bool complete;
  std::vector<Vapi_msg<Msg>, typename Vapi_msg<Msg>::Vapi_msg_allocator> set;
};

template <typename Req, typename Resp, typename... Args>
class Vapi_dump : public Vapi_common_req
{
  friend class Vapi_connection;

public:
  Vapi_dump (Vapi_connection *con, Args... args,
             std::function<vapi_error_e (Vapi_dump<Req, Resp, Args...> *)>
                 callback = nullptr)
      : Vapi_common_req{con}, request{con, vapi_alloc<Req> (con, args...)},
        result_set{con}, callback{callback}
  {
  }

  virtual ~Vapi_dump () {}

  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    if (id == vapi_msg_id_control_ping_reply)
      {
        con->msg_free (shm_data);
        result_set.mark_complete ();
        set_response_state (RESPONSE_READY);
        if (nullptr != callback)
          {
            return std::make_pair (callback (this), true);
          }
        return std::make_pair (VAPI_OK, true);
      }
    else
      {
        result_set.assign_response (id, shm_data);
      }
    return std::make_pair (VAPI_OK, false);
  }

  vapi_error_e execute () { return con->send_with_control_ping (this); }

  const Vapi_msg<Req> *get_request (void) const { return &request; }

  const Vapi_result_set<Resp> *get_result_set (void) const
  {
    return &result_set;
  }

private:
  Vapi_msg<Req> request;
  Vapi_result_set<Resp> result_set;
  std::function<vapi_error_e (Vapi_dump<Req, Resp, Args...> *)> callback;
};

template <typename Vapi_msg_resp>
class Vapi_event_registration : public Vapi_common_req
{
public:
  Vapi_event_registration (
      Vapi_connection *con,
      std::function<vapi_error_e (Vapi_event_registration<Vapi_msg_resp> *)>
          callback = nullptr) throw (Vapi_msg_not_available_exception)
      : Vapi_common_req{con}, result_set{con}, callback{callback}
  {
    if (!con->is_msg_available (Vapi_msg_resp::get_msg_id ()))
      {
        throw Vapi_msg_not_available_exception ();
      }
    con->register_event (this);
  }

  virtual ~Vapi_event_registration () { con->unregister_event (this); }

  virtual std::tuple<vapi_error_e, bool> assign_response (vapi_msg_id_t id,
                                                          void *shm_data)
  {
    result_set.assign_response (id, shm_data);
    if (shm_data)
      {
        set_response_state (RESPONSE_READY);
      }
    if (nullptr != callback)
      {
        return std::make_pair (callback (this), true);
      }
    return std::make_pair (VAPI_OK, true);
  }

  using resp_type = typename Vapi_msg_resp::shm_data_type;

  const Vapi_result_set<resp_type> *get_result_set (void) const
  {
    return &result_set;
  }

private:
  Vapi_result_set<resp_type> result_set;
  std::function<vapi_error_e (Vapi_event_registration<Vapi_msg_resp> *)>
      callback;
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
