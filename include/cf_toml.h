// cf_toml.h

#ifndef __CF_TOML_H_
#define __CF_TOML_H_


#if defined(__cplusplus)
extern "C" {
#endif

typedef struct toml_table_t toml_table_t;
typedef struct toml_array_t toml_array_t;


toml_table_t* cf_toml_open(const char*);

/* Parse a file. Return a table on success, or 0 otherwise. 
 * Caller must cf_toml_free(the-return-value) after use
 */
toml_table_t* cf_toml_parse_file(FILE*, size_t);

/* Parse a string containing the full config. 
 * Return a table on success, or 0 otherwise.
 * Caller must cf_toml_free(the-return-value) after use.
 */
toml_table_t* cf_toml_parse(char*/* NUL terminated */);

/* Free the table returned by cf_toml_parse() or cf_toml_parse_file() */
void cf_toml_free(toml_table_t*);

/* Retrieve the key in table at keyidx. Return 0 if out of range. */
const char* cf_toml_key_in(toml_table_t*,int);

/* Lookup table by key. Return the element or 0 if not found. */
const char* cf_toml_raw_in(toml_table_t*,const char*);
toml_array_t* cf_toml_array_in(toml_table_t*,const char*);
toml_table_t* cf_toml_table_in(toml_table_t*,const char*);

/* Return the array kind: 't'able, 'a'rray, 'v'alue */
char cf_toml_array_kind(toml_array_t*);

/* Return the number of elements in the array */
int cf_toml_array_nelem(toml_array_t*);

/* Return the key of an array */
const char* cf_toml_array_key(toml_array_t*);

/* Return the number of key-values in a table */
int cf_toml_table_nkval(toml_table_t*);

/* Return the number of arrays in a table */
int cf_toml_table_narr(toml_table_t*);

/* Return the number of sub-tables in a table */
int cf_toml_table_ntab(toml_table_t*);

/* Return the key of a table */
const char* cf_toml_table_key(toml_table_t*);

/* Deref array by index. Return the element at idx or 0 if out of range. */
const char* cf_toml_raw_at(toml_array_t*,int);
toml_array_t* cf_toml_array_at(toml_array_t*,int);
toml_table_t* cf_toml_table_at(toml_array_t*,int);


/* Raw to String. Caller must call free(ret) after use. 
 * Return 0 on success, -1 otherwise.
 */
int cf_toml_rtos(const char* s, char** ret);

/* Raw to Boolean. Return 0 on success, -1 otherwise. */
int cf_toml_rtob(const char* s, int* ret);

/* Raw to Integer. Return 0 on success, -1 otherwise. */
int cf_toml_rtoi(const char* s, int64_t* ret);

/* Raw to Double. Return 0 on success, -1 otherwise. */
int cf_toml_rtod(const char* s, double* ret);

/* Timestamp types. The year, month, day, hour, minute, second, z 
 * fields may be NULL if they are not relevant. e.g. In a DATE
 * type, the hour, minute, second and z fields will be NULLs.
 */
typedef struct toml_timestamp_t toml_timestamp_t;
struct toml_timestamp_t {
    struct { /* internal. do not use. */
	int year, month, day;
	int hour, minute, second;
	char z[10];
    } __buffer;
    int *year, *month, *day;
    int *hour, *minute, *second;
    char* z;
};

/* Raw to Timestamp. Return 0 on success, -1 otherwise. */
int cf_toml_rtots(const char* s, toml_timestamp_t* ret);

/* misc */
int cf_toml_utf8_to_ucs(const char*,int,int64_t*);
int cf_toml_ucs_to_utf8(int64_t code, char buf[6]);


#if defined(__cplusplus)
}
#endif

#endif /* __CF_TOML_H_ */
