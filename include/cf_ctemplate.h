// cf_ctemplate.h

#ifndef __CF_CTEMPLATE_H_
#define __CF_CTEMPLATE_H_

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct cf_tmpl_varlist cf_tmpl_varlist;
typedef struct cf_tmpl_loop  cf_tmpl_loop;
typedef struct cf_tmpl_fmtlist cf_tmpl_fmtlist;
typedef void (*cf_tmpl_fmtfunc) (const char *, FILE *);


cf_tmpl_varlist* cf_tmpl_add_var(cf_tmpl_varlist *varlist, ...);
cf_tmpl_varlist* cf_tmpl_add_loop(cf_tmpl_varlist *varlist, const char *name, cf_tmpl_loop *loop);
cf_tmpl_loop* cf_tmpl_add_varlist(cf_tmpl_loop *loop, cf_tmpl_varlist *varlist);
void cf_tmpl_free_varlist(cf_tmpl_varlist *varlist);
cf_tmpl_fmtlist* cf_tmpl_add_fmt(cf_tmpl_fmtlist *fmtlist, const char *name, cf_tmpl_fmtfunc fmtfunc);
void cf_tmpl_free_fmtlist(cf_tmpl_fmtlist *fmtlist);
int cf_tmpl_write(char *filename, char *tmplstr, const cf_tmpl_fmtlist *fmtlist, const cf_tmpl_varlist *varlist, FILE *out, FILE *errout);

void cf_tmpl_encode_entity(const char *value, FILE *out);
void cf_tmpl_encode_url(const char *value, FILE *out);


#if defined(__cplusplus)
}
#endif


#endif /* __CF_CTEMPLATE_H_ */
