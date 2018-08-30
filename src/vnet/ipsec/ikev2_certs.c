/*      $OpenBSD: ca.c,v 1.46 2017/10/30 09:53:27 patrick Exp $ */

/*
 * Copyright (c) 2010-2013 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>

#include <dirent.h>

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>

// to load and return X509 certificate from file name
X509 * ikev2_load_cert(u8 * file)
{

	X509* cert = NULL;
	BIO* certbio ;
	certbio = BIO_new(BIO_s_file());

	BIO_read_filename(certbio,file);

	if ( !(cert = PEM_read_bio_X509(certbio, NULL, 0 ,NULL))){
		cert = NULL ;
	}
	BIO_free_all(certbio);
	return cert ;
}

int ikev2_hash_pubkey(X509 *x509, u8 *md, unsigned int *size){
	EVP_PKEY		*pkey;
	u8	*buf = NULL;
	int		 		buflen;

	if (*size < SHA_DIGEST_LENGTH)
		return (-1);

	if(x509 == NULL)
		return -1;

	/*
	 * Generate a SHA-1 digest of the Subject Public Key Info
	 * element in the X.509 certificate, an ASN.1 sequence
	 * that includes the public key type (eg. RSA) and the
	 * public key value (see 3.7 of RFC4306).
	 */
	if ((pkey = X509_get_pubkey(x509)) == NULL)
		return (-1);
	buflen = i2d_PUBKEY(pkey, &buf);
	EVP_PKEY_free(pkey);
	if (buflen == 0)
		return (-1);
	if (!EVP_Digest(buf, buflen, md, size, EVP_sha1(), NULL)) {
		free(buf);
		return (-1);
	}
	free(buf);

	return (0);
}


// to verify certificate with given CA store
// 		returns 0 is verification succeed
// 		returns 1 is cerification failed
//		returns negative value is an error occured
int ikev2_ca_validate_cert(ca_store_t *store, X509 * cert){

	X509_STORE_CTX	 csc;
	int		 ret = -1, result, error;
	X509_NAME	*subject;
	const char	*errstr = "failed";

	if(cert == NULL){
		errstr = "given cert is null";
		goto done;
	}

	/* Certificate needs a valid subjectName */
	if ((subject = X509_get_subject_name(cert)) == NULL) {
		errstr = "invalid subject";
		goto done;
	}

	bzero(&csc, sizeof(csc));
	X509_STORE_CTX_init(&csc, store->ca_cas, cert, NULL);
	if (store->ca_cas->param->flags & X509_V_FLAG_CRL_CHECK) {
		X509_STORE_CTX_set_flags(&csc, X509_V_FLAG_CRL_CHECK);
		X509_STORE_CTX_set_flags(&csc, X509_V_FLAG_CRL_CHECK_ALL);
	}

	result = X509_verify_cert(&csc);
	error = csc.error;
	X509_STORE_CTX_cleanup(&csc);
	if (error != 0) {
		errstr = X509_verify_cert_error_string(error);
		goto done;
	}

	if (!result) {
		/* XXX should we accept self-signed certificates? */
		errstr = "rejecting self-signed certificate";
		goto done;
	}

	/* Success */
	ret = 0;
	errstr = "ok";

 done:
	if (cert != NULL)
		clib_warning("verification status for %s -> %.100s\n", cert->name, errstr);

	return (ret);
}

// to check if subject from cert matches the id
static int ikev2_ca_x509_subject_cmp(X509 *cert, X509_NAME * id_name){

	X509_NAME	*subject = NULL;
	int		 ret = -1;


	if ((subject = X509_get_subject_name(cert)) == NULL)
		return (-1);
	if (id_name  == NULL)
		return (-1);
	if (X509_NAME_cmp(subject, id_name) == 0)
		ret = 0;

	//X509_NAME_free(subject);
	return (ret);
}

// to check if a certificate with a given name exists in this store
// 		returns the certificate if it exists
//		return NULL otherwise
static X509 * ikev2_ca_by_subjectname( X509_STORE *ctx, X509_NAME *name){

	STACK_OF(X509_OBJECT)	*h;
	X509_OBJECT		*xo;
	X509			*cert;
	int			 i;

	h = ctx->objs;
	for (i = 0; i < sk_X509_OBJECT_num(h); i++) {
		xo = sk_X509_OBJECT_value(h, i);
		if (xo->type != X509_LU_X509)
			continue;

		cert = xo->data.x509;

		if (ikev2_ca_x509_subject_cmp(cert, name) == 0){
			return (cert);
		}
	}

	return (NULL);
}

//function to check is a given digest is part of a cert's ca path
//		returns 0 if the digest is found
//		returns 1 if not matchinf digest was found
//		returns negative value if an error occured
int ikev2_is_digest_in_ca_path(X509 * cert, u8 * md, X509_STORE * ca_store){

	if(md == NULL || cert == NULL || ca_store == NULL){
		return -1 ;
	}

	int ret = 1 ;
	X509 * temp_cert = cert;
	X509_NAME * old_issuer ;
	X509_NAME * issuer_name;
	u8 temp_md[CERTREQ_MD_SIZE];
	unsigned int len = CERTREQ_MD_SIZE ;

	if(md == NULL || cert == NULL || ca_store == NULL){
		return -1 ;
	}

	issuer_name = X509_get_issuer_name(temp_cert);

	do{

		if ((temp_cert = ikev2_ca_by_subjectname(ca_store, issuer_name)) == NULL){
			return -1 ;
		}

		ikev2_hash_pubkey(temp_cert, temp_md, &len);

		if(memcmp(temp_md,md,sizeof(temp_md))==0){
			ret = 0 ;
		}

		old_issuer = issuer_name ;
		issuer_name = X509_get_issuer_name(temp_cert);

	}while( X509_NAME_cmp(issuer_name,old_issuer) != 0 && ret == 1);

	return ret ;

}

// computes the digest for every CA
// concatenates everything and assigns this to km->ca_store->certreq
// 		returns the size of  *(km->ca_store->certreq)
//		returns -1 if an error occured
static int ikev2_gen_certreq(ikev2_main_t * km){

	u8 ** buf = km->ca_store->certreq ;
	ca_store_t * store = km->ca_store ;

	STACK_OF(X509_OBJECT)	*h;
	X509_OBJECT		*xo;
	X509			*ca;
	int			 i;
	int number_of_cas ;
	unsigned int total_len ;
	unsigned int md_len = CERTREQ_MD_SIZE ;
	u8 * md ;

	if(store == NULL){
		return -1 ;
	}
	if(store->ca_cas == NULL){
		return -1 ;
	}
	if(buf == NULL){
		return -1 ;
	}


	h = store->ca_cas->objs;
	number_of_cas = sk_X509_OBJECT_num(h) ;

	total_len = sizeof(u8)*md_len*number_of_cas ;

	if((*buf = calloc(total_len, sizeof(u8))) == NULL){
		return -1 ;
	}

	if ((md = malloc(md_len)) == NULL){
		return -1 ;
	}

	for (i = 0; i < sk_X509_OBJECT_num(h); i++) {
		xo = sk_X509_OBJECT_value(h, i);
		ca = xo->data.x509;

		clib_warning("Computing digest for %s", ca->name);

		ikev2_hash_pubkey(ca,md,&md_len);
		memcpy((*buf)+CERTREQ_MD_SIZE*i,md,md_len);
	}

	free(md);

	return total_len ;

}

// allocates memory and initialize ca_store_t
//		returns ca_store_t pointer
//		returns NULL is an error occured
ca_store_t * ikev2_init_store(){

	ca_store_t * res ;
	if ((res = calloc(1, sizeof(*res))) == NULL){
		clib_warning("Unable to allocate memory");
		return NULL;
	}

	if ((res->ca_cas = X509_STORE_new()) == NULL){
		clib_warning("init_store: failed to get ca store");
		return NULL ;
	}
	if ((res->ca_calookup = X509_STORE_add_lookup(res->ca_cas,
	    X509_LOOKUP_file())) == NULL){
		clib_warning("init_store: failed to add ca lookup");
		return NULL ;
	}


	if((res->certreq = malloc(sizeof(u8))) == NULL){
		clib_warning("init_store: failed init certreq");
		return NULL ;
	}

	return res ;

}

// this function can be used to set values for km->ca_store
//		returns 0 if everything went fine
//		returns -1 if an error occured
int ikev2_load_pki(ikev2_main_t * km){
	ca_store_t * store = km->ca_store ;
	DIR *dir ;
	char			 file[PATH_MAX];
	struct dirent		*entry;

	/*--- Load CAs ---*/
	if ((dir = opendir(CA_DIR)) == NULL){
        clib_warning("can not open %d dir",CA_DIR);
        return (-1);
    }


	while((entry = readdir(dir)) != NULL){

		if ((entry->d_type != DT_REG) &&
		    (entry->d_type != DT_LNK))
			continue;

		if (snprintf(file, sizeof(file), "%s%s",
		    CA_DIR, entry->d_name) == -1)
			continue;

		if(!X509_load_cert_file(store->ca_calookup,file,X509_FILETYPE_PEM)) {
			clib_warning("Error while loading ca file : %s ",entry->d_name);
			continue;
		}
		clib_warning("Loaded ca file : %s ",entry->d_name);

	}
	closedir(dir);

	/*--- Create certreq ---*/
	if((km->ca_store->certreq_size = ikev2_gen_certreq(km))== -1){
		clib_warning("failed to generate certreq");
	}

	/*--- Load CRLs ---*/
	if ((dir = opendir(CRL_DIR)) == NULL){
        clib_warning("can not open %d dir",CRL_DIR);
        return (-1);
    }

	while((entry = readdir(dir)) != NULL){

		if ((entry->d_type != DT_REG) &&
		    (entry->d_type != DT_LNK))
			continue;

		if (snprintf(file, sizeof(file), "%s%s",
		    CRL_DIR, entry->d_name) == -1)
			continue;

		if (!X509_load_crl_file(store->ca_calookup, file, X509_FILETYPE_PEM)){
			clib_warning("Error while loading crl file : %s ",entry->d_name);
			continue;
		}

		X509_STORE_set_flags(store->ca_cas, X509_V_FLAG_CRL_CHECK);

		clib_warning("Loaded crl file : %s ",entry->d_name);

	}
	closedir(dir);

	return 0 ;
}

// This functions frees an already allocated ca_store and reallocates memory for it
// then, all the pki is reloaded ( <=> refresh pki )
void ikev2_reset_pki(ikev2_main_t * km)
{
	ca_store_t * store = km->ca_store ;

	if (store->ca_cas != NULL)
		X509_STORE_free(store->ca_cas);

	if(*(store->certreq)!=NULL)
		free(*(store->certreq));

	if ((store->ca_cas = X509_STORE_new()) == NULL)
		clib_warning("ca_reset: failed to get ca store");
	if ((store->ca_calookup = X509_STORE_add_lookup(store->ca_cas,
	    X509_LOOKUP_file())) == NULL)
		clib_warning("ca_reset: failed to add ca lookup");

	if (ikev2_load_pki(km) != 0)
		clib_warning("ca_reset: reload");
}
