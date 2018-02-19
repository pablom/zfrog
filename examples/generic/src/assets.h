#ifndef __H_CF_ASSETS_H
#define __H_CF_ASSETS_H
extern const uint8_t asset_params_html[];
extern const uint32_t asset_len_params_html;
extern const time_t asset_mtime_params_html;
extern const char *asset_sha256_params_html;
int asset_serve_params_html(struct http_request *);
extern const uint8_t asset_style_css[];
extern const uint32_t asset_len_style_css;
extern const time_t asset_mtime_style_css;
extern const char *asset_sha256_style_css;
int asset_serve_style_css(struct http_request *);
extern const uint8_t asset_index_html[];
extern const uint32_t asset_len_index_html;
extern const time_t asset_mtime_index_html;
extern const char *asset_sha256_index_html;
int asset_serve_index_html(struct http_request *);
extern const uint8_t asset_private_test_html[];
extern const uint32_t asset_len_private_test_html;
extern const time_t asset_mtime_private_test_html;
extern const char *asset_sha256_private_test_html;
int asset_serve_private_test_html(struct http_request *);
extern const uint8_t asset_upload_html[];
extern const uint32_t asset_len_upload_html;
extern const time_t asset_mtime_upload_html;
extern const char *asset_sha256_upload_html;
int asset_serve_upload_html(struct http_request *);
extern const uint8_t asset_private_html[];
extern const uint32_t asset_len_private_html;
extern const time_t asset_mtime_private_html;
extern const char *asset_sha256_private_html;
int asset_serve_private_html(struct http_request *);

#endif
