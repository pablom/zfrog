// cf_pkcs11.c

#include <sys/param.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

#include "zfrog.h"
#include "cf_pkcs11.h"

#define CK_PTR *
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* Unix case */
#define CK_DEFINE_FUNCTION(returnType, name) \
returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (* name)

#include <pkcs11/pkcs11.h>

/* Forward function declaration */
static int p11_find_token_by_label( CK_FUNCTION_LIST_PTR flp, const char *label, CK_SLOT_ID* slot_id );
static void p11_open_session( CK_FUNCTION_LIST *flp , CK_SLOT_ID slot_id, CK_SESSION_HANDLE* psh );
static CK_ULONG p11_find_object_by_label(CK_FUNCTION_LIST_PTR flp, CK_SESSION_HANDLE sh, char *label,
                                          CK_OBJECT_CLASS obj_class, CK_OBJECT_HANDLE_PTR pObj, CK_ULONG size );

struct pkcs11_key {
    CK_SESSION_HANDLE sh;
    CK_OBJECT_HANDLE  oh;
};


struct pkcs11_cfg cf_pkcs11_cfg =
{
    .module_path = NULL,
    .password = NULL
};

/* Internal structure */
static struct {
    CK_FUNCTION_LIST* flp;
    CK_SESSION_HANDLE sh;
} p11_module = {
    .flp = NULL,
    .sh = CK_INVALID_HANDLE
};


/************************************************************************
 *  Helper function to find PKCS11 object in HSM
 ************************************************************************/
static CK_ULONG p11_find_object_by_label( CK_FUNCTION_LIST_PTR flp, CK_SESSION_HANDLE sh,
                                          char *label, CK_OBJECT_CLASS obj_class,
                                          CK_OBJECT_HANDLE_PTR pObj, CK_ULONG size )
{
    CK_ATTRIBUTE attrs[2];
    CK_ULONG count = 0;
    CK_RV rv;
    unsigned int nattrs = 0;

    /* Check incoming parameters */
    if( label == NULL )
        return count;

    /* Fill request attributes */
    if( obj_class == CKO_PRIVATE_KEY || obj_class == CKO_CERTIFICATE )
    {
        attrs[nattrs].type = CKA_CLASS;
        attrs[nattrs].pValue = &obj_class;
        attrs[nattrs].ulValueLen = sizeof(obj_class);
        nattrs++;
    }

    if( label )
    {
        attrs[nattrs].type = CKA_LABEL;
        attrs[nattrs].pValue = /*(void *) (char*)*/(CK_VOID_PTR)label;
        attrs[nattrs].ulValueLen = strlen(label);
        nattrs++;
    }

    /* Init find function */
    if( (rv = flp->C_FindObjectsInit(sh, attrs, nattrs)) != CKR_OK )
    {
        //p11_perror("C_FindObjectsInit", rv);
        return count;
    }

    if( pObj == NULL || size == 0 )
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_ULONG rt_count = 0;
        CK_OBJECT_HANDLE_PTR obj_ar = NULL;

        /* Iterate all object */
        while( 1 )
        {
            if( (rv = flp->C_FindObjects(sh, &obj, 1, &rt_count)) != CKR_OK )
            {
                /* Delete temporary object array */
                free( obj_ar );
                obj_ar = NULL;
                count = 0;
                //p11_perror("C_FindObjects", rv);
                break;
            }

            if( rt_count == 0 )
                break;

            obj_ar = realloc( obj_ar, count + 1);
            obj_ar[count] = obj;
            count++;
        }

        /* Set return array */
        //*pObj = obj_ar;
    }
    else
    {
        //CK_OBJECT_HANDLE_PTR obj_ar = *pObj;

        if( (rv = flp->C_FindObjects(sh, pObj, size, &count)) == CKR_OK )
            cf_log(LOG_NOTICE, "pkcs11 oject %s found", label );

//         if( (rv = flp->C_FindObjects(sh, obj_ar, size, &count)) != CKR_OK )
//             p11_perror("C_FindObjects", rv);
    }

    flp->C_FindObjectsFinal( sh );

    /* End find function */
//    if( (rv = flp->C_FindObjectsFinal( sh )) != CKR_OK )
//        p11_perror("C_FindObjectsFinal", rv);

    /* Return number of objects found */
    return count;
}
/************************************************************************
 *  Helper function to open PKCS11 session
 ************************************************************************/
static void p11_open_session( CK_FUNCTION_LIST* flp, CK_SLOT_ID slot_id, CK_SESSION_HANDLE* psh )
{
    CK_RV rv;
    /* create a USER/SO R/W session */
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    if( (rv = flp->C_OpenSession( slot_id , flags, NULL, NULL, psh )) != CKR_OK ) {
        cf_fatal("failed C_OpenSession: 0x%08X", rv);
    }

    if( (rv = flp->C_Login( *psh, CKU_USER, (unsigned char*)cf_pkcs11_cfg.password, strlen(cf_pkcs11_cfg.password) )) != CKR_OK ) {
        cf_fatal("failed C_Login: 0x%08X", rv);
    }

    cf_log(LOG_NOTICE, "pkcs11 session opened");
}
/************************************************************************
 *  Helper function to find token by label
 ************************************************************************/
static int p11_find_token_by_label( CK_FUNCTION_LIST_PTR flp, const char *label, CK_SLOT_ID* slot_id )
{
    int rc = -1;  /* Return error code */
    CK_RV rv;
    CK_ULONG  nslots = 0; /* Number of slots */

    if( (rv = flp->C_GetSlotList(0, NULL_PTR, &nslots)) == CKR_OK && nslots > 0 )
    {
        /* Allocate array for all available slots */
        CK_SLOT_ID* pslots = mem_malloc(sizeof(CK_SLOT_ID) * nslots);

        if( (rv = flp->C_GetSlotList(0, pslots, &nslots)) == CKR_OK )
        {
            CK_ULONG i = 0;
            /* Get input label length */
            int label_len = strlen( label );

            for( i = 0; i < nslots; i++ )
            {
                CK_SLOT_INFO   s_info;
                CK_TOKEN_INFO  info;

                /* Get slot info */
                if( (rv = flp->C_GetSlotInfo(pslots[i], &s_info)) == CKR_OK )
                {
                    if( (s_info.flags & CKF_TOKEN_PRESENT) == 0 )
                        continue;

                  /*  if( s_info.flags & CKF_HW_SLOT == 0 )
                    {
                        show_error(stdout,"Software slot, skipping");
                        continue;
                    }
                 */
                    if( (rv = flp->C_GetTokenInfo( pslots[i], &info )) == CKR_OK )
                    {
                        if( memcmp(info.label, label, label_len) == 0 || strcmp( (char*)info.label, label ) == 0 )
                        {
                            *slot_id = pslots[i];
                            rc = 0;
                            break;
                        }
                    }
                }
            }
        }

        /* Delete temporary array */
        mem_free( pslots );
    }

    return rc;
}

void cf_init_pkcs11_module(void)
{
    if( cf_pkcs11_cfg.module_path )
    {
        CK_RV rv;
        CK_FUNCTION_LIST* flp = NULL;
        CK_RV (*c_get_function_list)(CK_FUNCTION_LIST**);
        void *ptr = NULL;

        /* Try to load module */
        cf_module_load( cf_pkcs11_cfg.module_path, NULL, CF_MODULE_NATIVE );

        if( (ptr = cf_module_getsym("C_GetFunctionList", NULL)) == NULL )
            return;

        memmove(&c_get_function_list, &(ptr), sizeof(void *));

        if( c_get_function_list )
        {
            if( (rv = c_get_function_list( &flp)) == CKR_OK )
            {
                /* Init module global structure */
                p11_module.flp = flp;
                cf_pkcs11_cfg.password = mem_strdup("qwerty");

                /* Initialize HSM session */
                if( (rv = flp->C_Initialize(NULL)) != CKR_OK ) {
                    cf_fatal("failed C_Initialize: 0x%08X", rv);
                }

                cf_log(LOG_NOTICE, "pkcs11 module [%s] loaded", cf_pkcs11_cfg.module_path);
                return;
            }
        }
    }
}

void *cf_pkcs11_load_privatekey( char* privkey )
{
    struct pkcs11_key* pkey = NULL;

    if( privkey && p11_module.flp )
    {
        char* pch = strchr(privkey,':');

        if( pch )
        {
            CK_SLOT_ID slot_id;
            char* privkey_label = pch + 1;
            *pch = 0;

            if( !p11_find_token_by_label(p11_module.flp, privkey, &slot_id) )
            {
                CK_OBJECT_HANDLE obj;
                CK_SESSION_HANDLE sh = CK_INVALID_HANDLE;
                p11_open_session(p11_module.flp, slot_id, &sh );

                p11_find_object_by_label( p11_module.flp, sh, privkey_label, CKO_PRIVATE_KEY, &obj, 1);

                pkey = mem_malloc( sizeof(*pkey) );
                pkey->oh = obj;
                pkey->sh = sh;
            }
        }
    }

    return pkey;
}

int cf_pkcs11_private_encrypt(void* ctx, const void* data, int data_len, unsigned char* to )
{
    CK_RV rv;
    struct pkcs11_key* pkey = (struct pkcs11_key*) ctx;
    CK_MECHANISM  mech = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_ULONG  enc_len = 0;

    if( (rv = p11_module.flp->C_SignInit(pkey->sh, &mech, pkey->oh)) == CKR_OK )
    {
        if( (rv = p11_module.flp->C_Sign(pkey->sh, data, data_len, NULL_PTR, &enc_len)) == CKR_OK)
        {
            if( (rv = p11_module.flp->C_Sign(pkey->sh, data, data_len, to, &enc_len)) == CKR_OK )
                return enc_len;

            cf_log(LOG_NOTICE,"failed C_Sign(1): 0x%08X", (unsigned int)rv);
        }
        else {
            cf_log(LOG_NOTICE,"failed C_Sign(0): 0x%08X", (unsigned int)rv);
        }
    }
    else {
        cf_log(LOG_NOTICE,"failed C_SignInit: 0x%08X", (unsigned int)rv);
    }


    return enc_len;
}



