/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>

#include <vnet/fib/fib_attached_export.h>
#include <vnet/fib/fib_entry_cover.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_entry_delegate.h>
#include <vnet/dpo/drop_dpo.h>

/**
 * A description of the need to import routes from the export table
 */
typedef struct fib_ae_import_t_
{
    /**
     * The entry in the export table that this importer
     * is importing covereds from
     */
    fib_node_index_t faei_export_entry;

    /**
     * The attached entry in the import table
     */
    fib_node_index_t faei_import_entry;
    /**
     * the sibling index on the cover
     */
    u32 faei_export_sibling;

    /**
     * The index of the exporter tracker. Not set if the
     * export entry is not valid for export
     */
    fib_node_index_t faei_exporter;

    /**
     * A vector/list of imported entry indicies
     */
    fib_node_index_t *faei_importeds;

    /**
     * The FIB index and prefix we are tracking
     */
    fib_node_index_t faei_export_fib;
    fib_prefix_t faei_prefix;

    /**
     * The FIB index we are importing into
     */
    fib_node_index_t faei_import_fib;
} fib_ae_import_t;

/**
 * A description of the need to export routes to one or more export tables
 */
typedef struct fib_ae_export_t_ {
    /**
     * The vector/list of import tracker indicies
     */
    fib_node_index_t *faee_importers;

    /**
     * THe connected entry this export is acting on behalf of
     */
    fib_node_index_t faee_ei;

    /**
     * Reference counting locks
     */
    u32 faee_locks;
} fib_ae_export_t;

/*
 * memory pools for the importers and exporters
 */
static fib_ae_import_t *fib_ae_import_pool;
static fib_ae_export_t *fib_ae_export_pool;

static fib_ae_export_t *
fib_entry_ae_add_or_lock (fib_node_index_t connected)
{
    fib_entry_delegate_t *fed;
    fib_ae_export_t *export;
    fib_entry_t *entry;

    entry = fib_entry_get(connected);
    fed = fib_entry_delegate_find(entry,
                                  FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);

    if (NULL == fed)
    {
        fed = fib_entry_delegate_find_or_add(entry,
                                             FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);
	pool_get(fib_ae_export_pool, export);
	clib_memset(export, 0, sizeof(*export));

	fed->fd_index = (export - fib_ae_export_pool);
	export->faee_ei = connected;
    }
    else
    {
	export = pool_elt_at_index(fib_ae_export_pool, fed->fd_index);
    }

    export->faee_locks++;

    return (export);
}

static void
fib_entry_import_remove (fib_ae_import_t *import,
			 fib_node_index_t entry_index)
{
    u32 index;

    /*
     * find the index in the vector of the entry we are removing
     */
    index = vec_search(import->faei_importeds, entry_index);

    if (index < vec_len(import->faei_importeds))
    {
	/*
	 * this is an entry that was previously imported
	 */
	fib_table_entry_special_remove(import->faei_import_fib,
				       fib_entry_get_prefix(entry_index),
				       FIB_SOURCE_AE);

	fib_entry_unlock(entry_index);
	vec_del1(import->faei_importeds, index);
    }
}

static void
fib_entry_import_add (fib_ae_import_t *import,
		      fib_node_index_t entry_index)
{
    fib_node_index_t *existing;
    fib_prefix_t prefix;

    /*
     * ensure we only add the exported entry once, since
     * sourcing prefixes in the table is reference counted
     */
    vec_foreach(existing, import->faei_importeds)
    {
	if (*existing == entry_index)
	{
	    return;
	}
    }

    /*
     * this is the first time this export entry has been imported
     * Add it to the import FIB and to the list of importeds.
     * make a copy of the prefix in case the underlying entry reallocs.
     */
    fib_prefix_copy(&prefix, fib_entry_get_prefix(entry_index));

    /*
     * don't import entries that have the same prefix the import entry
     */
    if (0 != fib_prefix_cmp(&prefix, &import->faei_prefix))
    {
        const dpo_id_t *dpo;

        dpo = fib_entry_contribute_ip_forwarding(entry_index);

        if (dpo_id_is_valid(dpo) && !dpo_is_drop(dpo))
        {
            fib_table_entry_special_dpo_add(import->faei_import_fib,
                                            &prefix,
                                            FIB_SOURCE_AE,
                                            (fib_entry_get_flags(entry_index) |
                                             FIB_ENTRY_FLAG_EXCLUSIVE),
                                            load_balance_get_bucket(dpo->dpoi_index, 0));

            fib_entry_lock(entry_index);
            vec_add1(import->faei_importeds, entry_index);
        }
        /*
         * else
         *   the entry currently has no valid forwarding. when it
         * does it will export itself
         */
    }
}

/**
 * Call back when walking a connected prefix's covered prefixes for import
 */
static walk_rc_t
fib_entry_covered_walk_import (fib_entry_t *cover,
			       fib_node_index_t covered,
			       void *ctx)
{
    fib_ae_import_t *import = ctx;

    fib_entry_import_add(import, covered);

    return (WALK_CONTINUE);
}

/*
 * fib_entry_ae_import_add
 *
 * Add an importer to a connected entry
 */
static void
fib_ae_export_import_add (fib_ae_export_t *export,
			  fib_ae_import_t *import)
{
    fib_entry_t *entry;

    import->faei_exporter = (export - fib_ae_export_pool);
    entry = fib_entry_get(export->faee_ei);

    fib_entry_cover_walk(entry,
			 fib_entry_covered_walk_import,
			 import);
}

void
fib_attached_export_import (fib_entry_t *fib_entry,
			    fib_node_index_t export_fib)
{
    fib_entry_delegate_t *fed;
    fib_ae_import_t *import;
    fib_node_index_t fei;

    /*
     * save index for later post-realloc retrieval
     */
    fei = fib_entry_get_index(fib_entry);

    pool_get(fib_ae_import_pool, import);

    import->faei_import_fib = fib_entry->fe_fib_index;
    import->faei_export_fib = export_fib;
    import->faei_prefix = fib_entry->fe_prefix;
    import->faei_import_entry = fib_entry_get_index(fib_entry);
    import->faei_export_sibling = ~0;

    /*
     * do an exact match in the export table
     */
    import->faei_export_entry =
	fib_table_lookup_exact_match(import->faei_export_fib,
				     &import->faei_prefix);

    if (FIB_NODE_INDEX_INVALID == import->faei_export_entry)
    {
	/*
	 * no exact matching entry in the export table. can't be good.
	 * track the next best thing
	 */
	import->faei_export_entry =
	    fib_table_lookup(import->faei_export_fib,
			     &import->faei_prefix);
	import->faei_exporter = FIB_NODE_INDEX_INVALID;
    }
    else
    {
	/*
	 * found the entry in the export table. import the
	 * the prefixes that it covers.
	 * only if the prefix found in the export FIB really is
	 * attached do we want to import its covered
	 */
	if (FIB_ENTRY_FLAG_ATTACHED &
	    fib_entry_get_flags_i(fib_entry_get(import->faei_export_entry)))
	{
	    fib_ae_export_t *export;

	    export = fib_entry_ae_add_or_lock(import->faei_export_entry);
	    vec_add1(export->faee_importers, (import - fib_ae_import_pool));
	    fib_ae_export_import_add(export, import);
	}
    }

    /*
     * track the entry in the export table so we can update appropriately
     * when it changes.
     * Exporting prefixes will have allocated new fib_entry_t objects, so the pool
     * may have realloc'd.
     */
    fib_entry = fib_entry_get(fei);
    import->faei_export_sibling =
	fib_entry_cover_track(fib_entry_get(import->faei_export_entry), fei);

    fed = fib_entry_delegate_find_or_add(fib_entry,
                                         FIB_ENTRY_DELEGATE_ATTACHED_IMPORT);
    fed->fd_index = (import - fib_ae_import_pool);
}

/**
 * \brief All the imported entries need to be purged
 */
void
fib_attached_export_purge (fib_entry_t *fib_entry)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(fib_entry,
                                  FIB_ENTRY_DELEGATE_ATTACHED_IMPORT);

    if (NULL != fed)
    {
 	fib_node_index_t *import_index;
	fib_entry_t *export_entry;
	fib_ae_import_t *import;
	fib_ae_export_t *export;

	import = pool_elt_at_index(fib_ae_import_pool, fed->fd_index);

	/*
	 * remove each imported entry
	 */
	vec_foreach(import_index, import->faei_importeds)
	{
	    fib_table_entry_delete(import->faei_import_fib,
				   fib_entry_get_prefix(*import_index),
				   FIB_SOURCE_AE);
	    fib_entry_unlock(*import_index);
	}
	vec_free(import->faei_importeds);

	/*
	 * stop tracking the export entry
	 */
	if (~0 != import->faei_export_sibling)
	{
	    fib_entry_cover_untrack(fib_entry_get(import->faei_export_entry),
				    import->faei_export_sibling);
	}
	import->faei_export_sibling = ~0;

	/*
	 * remove this import tracker from the export's list,
	 * if it is attached to one. It won't be in the case the tracked
	 * export entry is not an attached exact match.
	 */
	if (FIB_NODE_INDEX_INVALID != import->faei_exporter)
	{
            fib_entry_delegate_t *fed;

	    export_entry = fib_entry_get(import->faei_export_entry);

            fed = fib_entry_delegate_find(export_entry,
                                          FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);
            ALWAYS_ASSERT(NULL != fed);

	    export = pool_elt_at_index(fib_ae_export_pool, fed->fd_index);

	    u32 index = vec_search(export->faee_importers,
				   (import - fib_ae_import_pool));

	    ASSERT(index < vec_len(export->faee_importers));
	    vec_del1(export->faee_importers, index);

	    /*
	     * free the exporter if there are no longer importers
	     */
	    if (0 == --export->faee_locks)
	    {
		pool_put(fib_ae_export_pool, export);
                fib_entry_delegate_remove(export_entry,
                                          FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);
	    }
	}

	/*
	 * free the import tracker
	 */
	pool_put(fib_ae_import_pool, import);
        fib_entry_delegate_remove(fib_entry,
                                  FIB_ENTRY_DELEGATE_ATTACHED_IMPORT);
    }
}

void
fib_attached_export_covered_added (fib_entry_t *cover,
				   fib_node_index_t covered)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(cover,
                                  FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);

    if (NULL != fed)
    {
	/*
	 * the covering prefix is exporting to other tables
	 */
 	fib_node_index_t *import_index;
	fib_ae_import_t *import;
	fib_ae_export_t *export;

	export = pool_elt_at_index(fib_ae_export_pool, fed->fd_index);

	/*
	 * export the covered entry to each of the importers
	 */
	vec_foreach(import_index, export->faee_importers)
	{
	    import = pool_elt_at_index(fib_ae_import_pool, *import_index);

	    fib_entry_import_add(import, covered);
	}
    }
}

void
fib_attached_export_covered_removed (fib_entry_t *cover,
				     fib_node_index_t covered)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(cover,
                                  FIB_ENTRY_DELEGATE_ATTACHED_EXPORT);

    if (NULL != fed)
    {
	/*
	 * the covering prefix is exporting to other tables
	 */
 	fib_node_index_t *import_index;
	fib_ae_import_t *import;
	fib_ae_export_t *export;

	export = pool_elt_at_index(fib_ae_export_pool, fed->fd_index);

	/*
	 * remove the covered entry from each of the importers
	 */
	vec_foreach(import_index, export->faee_importers)
	{
	    import = pool_elt_at_index(fib_ae_import_pool, *import_index);

	    fib_entry_import_remove(import, covered);
	}
    }
}

static void
fib_attached_export_cover_modified_i (fib_entry_t *fib_entry)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(fib_entry,
                                  FIB_ENTRY_DELEGATE_ATTACHED_IMPORT);

    if (NULL != fed)
    {
	fib_ae_import_t *import;
	u32 export_fib;

	/*
	 * safe the temporaries we need from the existing import
	 * since it will be toast after the purge.
	 */
	import = pool_elt_at_index(fib_ae_import_pool, fed->fd_index);
	export_fib = import->faei_export_fib;

	/*
	 * keep it simple. purge anything that was previously imported.
	 * then re-evaluate the need to import.
	 */
	fib_attached_export_purge(fib_entry);
	fib_attached_export_import(fib_entry, export_fib);
    }
}

/**
 * \brief If this entry is tracking a cover (in another table)
 *        then that cover has changed. re-evaluate import.
 */
void
fib_attached_export_cover_change (fib_entry_t *fib_entry)
{
    fib_attached_export_cover_modified_i(fib_entry);
}

/**
 * \brief If this entry is tracking a cover (in another table)
 *        then that cover has been updated. re-evaluate import.
 */
void
fib_attached_export_cover_update (fib_entry_t *fib_entry)
{
    fib_attached_export_cover_modified_i(fib_entry);
}

u8*
fib_ae_import_format (fib_node_index_t impi,
		      u8* s)
{
    fib_node_index_t *index;
    fib_ae_import_t *import;

    import = pool_elt_at_index(fib_ae_import_pool, impi);

    s = format(s, "\n  Attached-Import:%d:[", (import - fib_ae_import_pool));
    s = format(s, "export-prefix:%U ", format_fib_prefix, &import->faei_prefix);
    s = format(s, "export-entry:%d ", import->faei_export_entry);
    s = format(s, "export-sibling:%d ", import->faei_export_sibling);
    s = format(s, "exporter:%d ", import->faei_exporter);
    s = format(s, "export-fib:%d ", import->faei_export_fib);

    s = format(s, "import-entry:%d ", import->faei_import_entry);
    s = format(s, "import-fib:%d ", import->faei_import_fib);

    s = format(s, "importeds:[");
    vec_foreach(index, import->faei_importeds)
    {
        s = format(s, "%d, ", *index);
    }
    s = format(s, "]]");

    return (s);
}

u8*
fib_ae_export_format (fib_node_index_t expi,
		      u8* s)
{
    fib_node_index_t *index;
    fib_ae_export_t *export;

    export = pool_elt_at_index(fib_ae_export_pool, expi);

    s = format(s, "\n  Attached-Export:%d:[", (export - fib_ae_export_pool));
    s = format(s, "export-entry:%d ", export->faee_ei);

    s = format(s, "importers:[");
    vec_foreach(index, export->faee_importers)
    {
        s = format(s, "%d, ", *index);
    }
    s = format(s, "]]");

    return (s);
}
