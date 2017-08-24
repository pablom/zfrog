// cf_pkcs11.h


#ifndef __CF_PKCS11_H__
#define __CF_PKCS11_H__

#if defined(__cplusplus)
extern "C" {
#endif


struct pkcs11_cfg
{
    char *module_path;
    char *password;
};

extern struct pkcs11_cfg  cf_pkcs11_cfg;


/* Load & init PKCS11 module  */
void cf_init_pkcs11_module(void);

void* cf_pkcs11_load_privatekey( char* privkey );

int cf_pkcs11_private_encrypt(void* ctx, const void *data, int data_len, unsigned char* to );

#if defined(__cplusplus)
}
#endif

#endif // __CF_PKCS11_H__
