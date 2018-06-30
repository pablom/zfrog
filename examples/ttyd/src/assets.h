#ifndef __H_CF_ASSETS_H
#define __H_CF_ASSETS_H
extern const uint8_t asset_frontend_html[];
extern const uint32_t asset_len_frontend_html;
extern const time_t asset_mtime_frontend_html;
extern const char *asset_sha256_frontend_html;
int asset_serve_frontend_html(struct http_request *);

#endif
