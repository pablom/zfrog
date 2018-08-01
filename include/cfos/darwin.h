// darwin.h

#ifndef __DARWIN__H_
#define __DARWIN__H_

#undef daemon
extern int daemon(int, int);

#define daemon portability_is_king

#define st_mtim		st_mtimespec

#endif /* !__DARWIN__H_ */
