/* MACIP ACL API handlers */

static void
vl_api_macip2_update_t_handler (vl_api_macip2_update_t * mp)
{
  vl_api_macip2_update_reply_t *rmp;
  int rv;
  u32 acl_list_index = ntohl (mp->acl_index);
  u32 acl_count = ntohl (mp->count);
  u32 expected_len = sizeof (*mp) + acl_count * sizeof (mp->r[0]);

  if (verify_message_len (mp, expected_len, "macip_acl2_update"))
    {
      rv = macip_add (acl_count, mp->r, &acl_list_index, mp->tag);
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MACIP2_UPDATE_REPLY,
  ({
    rmp->acl_index = htonl(acl_list_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_macip2_del_t_handler (vl_api_macip2_del_t * mp)
{
  vl_api_macip2_del_reply_t *rmp;
  int rv;

  rv = macip_del (ntohl (mp->acl_index));

  REPLY_MACRO (VL_API_MACIP2_DEL_REPLY);
}

static void
vl_api_macip2_bind_t_handler (vl_api_macip2_bind_t * mp)
{
  vl_api_macip2_bind_reply_t *rmp;
  int rv = -1;

  VALIDATE_SW_IF_INDEX (mp);

  rv = macip_bind (ntohl (mp->sw_if_index), ntohl (mp->acl_index));

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_MACIP2_BIND_REPLY);
}

static void
send_macip_acl_details (acl2_main_t * am, vl_api_registration_t * reg,
			macip_acl_t * acl, u32 context)
{
  vl_api_macip2_details_t *mp;
  vl_api_macip2_rule_t *rule;
  macip_acl_match_t *mam;
  macip_acl_main_t *mm;
  vnet_link_t linkt;
  match_rule_t *mr;
  u32 i, n_rules;

  mm = &macip_acl_main;

  n_rules = (match_list_length (&acl->matches[VNET_LINK_IP4].ml) +
	     match_list_length (&acl->matches[VNET_LINK_IP6].ml));

  u32 msg_size = sizeof (*mp) + (sizeof (mp->r[0]) * n_rules);

  mp = vl_msg_api_alloc_zero (msg_size);
  mp->_vl_msg_id = ntohs (VL_API_MACIP2_DETAILS + am->msg_id_base);

  /* fill in the message */
  mp->context = context;

  memcpy (mp->tag, acl->tag, clib_min (sizeof (mp->tag), vec_len (acl->tag)));
  mp->count = htonl (n_rules);
  mp->acl_index = htonl (acl - mm->macip_acls);
  i = 0;

  /* *INDENT-OFF* */
  FOR_EACH_MACIP_IP_LINK_W_RULES(acl, linkt, mam,
  ({
    vec_foreach(mr, mam->ml.ml_rules) {
      rule = &mp->r[i];

      // FIXME
      rule->is_permit = 1;	//r->is_permit;
      match_rule_mask_ip_mac_encode(mr, &rule->rule);
      i++;
    }
  }));
  /* *INDENT-ON* */

  vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_macip2_dump_t_handler (vl_api_macip2_dump_t * mp)
{
  macip_acl_main_t *mm = &macip_acl_main;
  acl2_main_t *am = &acl2_main;
  macip_acl_t *acl;

  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (mp->acl_index == ~0)
    {
      /* Just dump all ACLs for now, with sw_if_index = ~0 */
      /* *INDENT-OFF* */
      pool_foreach (acl, mm->macip_acls,
        ({
          send_macip_acl_details (am, reg, acl, mp->context);
        }));
      /* *INDENT-ON* */
    }
  else
    {
      u32 acl_index = ntohl (mp->acl_index);
      if (!pool_is_free_index (mm->macip_acls, acl_index))
	{
	  acl = pool_elt_at_index (mm->macip_acls, acl_index);
	  send_macip_acl_details (am, reg, acl, mp->context);
	}
    }
}

static void
send_macip_acl_bind_details (acl_main_t * am,
			     vl_api_registration_t * reg,
			     u32 sw_if_index, u32 acl_index, u32 context)
{
  vl_api_macip2_bind_details_t *rmp;
  /* at this time there is only ever 1 mac ip acl per interface */
  int msg_size = sizeof (*rmp) + sizeof (rmp->acls[0]);

  rmp = vl_msg_api_alloc (msg_size);
  clib_memset (rmp, 0, msg_size);
  rmp->_vl_msg_id = ntohs (VL_API_MACIP2_BIND_DETAILS + am->msg_id_base);

  /* fill in the message */
  rmp->context = context;
  rmp->count = 1;
  rmp->sw_if_index = htonl (sw_if_index);
  rmp->acls[0] = htonl (acl_index);

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_macip2_bind_dump_t_handler (vl_api_macip2_bind_dump_t * mp)
{
  vl_api_registration_t *reg;
  macip_acl_main_t *mm = &macip_acl_main;
  acl_main_t *am = &acl_main;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  if (sw_if_index == ~0)
    {
      vec_foreach_index (sw_if_index, mm->macip_acl_by_sw_if_index)
      {
	if (~0 != mm->macip_acl_by_sw_if_index[sw_if_index])
	  {
	    send_macip_acl_bind_details (am, reg, sw_if_index,
					 mm->macip_acl_by_sw_if_index
					 [sw_if_index], mp->context);
	  }
      }
    }
  else
    {
      if (vec_len (mm->macip_acl_by_sw_if_index) > sw_if_index)
	{
	  send_macip_acl_bind_details (am, reg, sw_if_index,
				       mm->macip_acl_by_sw_if_index
				       [sw_if_index], mp->context);
	}
    }
}

