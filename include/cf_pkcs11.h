// cf_pkcs11.h

#ifndef __CF_PKCS11_H__
#define __CF_PKCS11_H__


#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
//#include <unistd.h>
#include <string.h>

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


struct pkcs11_cfg
{
    char *module_path;
    char *password;
};

extern struct pkcs11_cfg  cf_pkcs11_cfg;


/* Load & init PKCS11 module  */
void cf_init_pkcs11_module(void);

void* cf_pkcs11_load_privatekey( char* privkey );

int cf_pkcs11_rsa_private_encrypt(void* ctx, const void *data, int data_len, unsigned char* to, int padding );

/* Return PKCS11 object's attribute */
int cf_pkcs11_get_object_attribute(void*,uint32_t,void**,size_t*);

#if defined(__cplusplus)
}
#endif

#endif // __CF_PKCS11_H__
