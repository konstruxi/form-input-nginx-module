#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include <ndk.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define form_urlencoded_type "application/x-www-form-urlencoded"
#define form_urlencoded_type_len (sizeof(form_urlencoded_type) - 1)


typedef struct {
    unsigned        used;  /* :1 */
} ngx_http_form_input_main_conf_t;


typedef struct {
    unsigned          done:1;
    unsigned          waiting_more_body:1;
} ngx_http_form_input_ctx_t;


static ngx_int_t ngx_http_set_form_input(ngx_http_request_t *r, ngx_str_t *res,
    ngx_http_variable_value_t *v);
static char *ngx_http_set_form_input_conf_handler(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static void *ngx_http_form_input_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_form_input_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_form_input_handler(ngx_http_request_t *r);
static void ngx_http_form_input_post_read(ngx_http_request_t *r);
static ngx_int_t ngx_http_form_input_arg(ngx_http_request_t *r, u_char *name,
    size_t len, ngx_str_t *value, ngx_flag_t multi);

static ngx_int_t ngx_http_form_input_json(ngx_http_request_t *r, u_char *name,
    size_t len, ngx_str_t *value, ngx_flag_t multi);


static ngx_command_t ngx_http_form_input_commands[] = {

    { ngx_string("set_form_input"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_set_form_input_conf_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_form_input_multi"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_set_form_input_conf_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_form_input_json"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_set_form_input_conf_handler,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_form_input_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_form_input_init,               /* postconfiguration */

    ngx_http_form_input_create_main_conf,   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t ngx_http_form_input_module = {
    NGX_MODULE_V1,
    &ngx_http_form_input_module_ctx,        /* module context */
    ngx_http_form_input_commands,           /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit precess */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_set_form_input(ngx_http_request_t *r, ngx_str_t *res,
    ngx_http_variable_value_t *v)
{
    ngx_http_form_input_ctx_t           *ctx;
    ngx_int_t                            rc;

    dd_enter();

    dd("set default return value");
    ngx_str_set(res, "");

    if (r->done) {
        dd("request done");
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_form_input_module);

    if (ctx == NULL) {
        dd("ndk handler:null ctx");
        return NGX_OK;
    }

    if (!ctx->done) {
        dd("ctx not done");
        return NGX_OK;
    }

    rc = ngx_http_form_input_arg(r, v->data, v->len, res, 0);

    return rc;
}


static ngx_int_t
ngx_http_set_form_input_multi(ngx_http_request_t *r, ngx_str_t *res,
    ngx_http_variable_value_t *v)
{
    ngx_http_form_input_ctx_t           *ctx;
    ngx_int_t                            rc;

    dd_enter();

    dd("set default return value");
    ngx_str_set(res, "");

    /* dd("set default return value"); */

    if (r->done) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_form_input_module);

    if (ctx == NULL) {
        dd("ndk handler:null ctx");
        return NGX_OK;
    }

    if (!ctx->done) {
        dd("ctx not done");
        return NGX_OK;
    }

    rc = ngx_http_form_input_arg(r, v->data, v->len, res, 1);

    return rc;
}


/* fork from ngx_http_arg.
 * read argument(s) with name arg_name and length arg_len into value variable,
 * if multi flag is set, multi arguments with name arg_name will be read and
 * stored in an ngx_array_t struct, this can be operated by directives in
 * array-var-nginx-module */
static ngx_int_t
ngx_http_form_input_arg(ngx_http_request_t *r, u_char *arg_name, size_t arg_len,
    ngx_str_t *value, ngx_flag_t multi)
{
    u_char              *p, *v, *last, *buf;
    ngx_chain_t         *cl;
    size_t               len = 0;
    ngx_array_t         *array = NULL;
    ngx_str_t           *s;
    ngx_buf_t           *b;

    if (multi) {
        array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
        if (array == NULL) {
            return NGX_ERROR;
        }
        value->data = (u_char *)array;
        value->len = sizeof(ngx_array_t);

    } else {
        ngx_str_set(value, "");
    }

    /* we read data from r->request_body->bufs */
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        dd("empty rb or empty rb bufs");
        return NGX_OK;
    }

    if (r->request_body->bufs->next != NULL) {
        /* more than one buffer...we should copy the data out... */
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;

            if (b->in_file) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "form-input: in-file buffer found. aborted. "
                              "consider increasing your "
                              "client_body_buffer_size setting");

                return NGX_OK;
            }

            len += b->last - b->pos;
        }

        dd("len=%d", (int) len);

        if (len == 0) {
            return NGX_OK;
        }

        buf = ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }

        dd("p - buf = %d, last - buf = %d", (int) (p - buf),
           (int) (last - buf));

        dd("copied buf (len %d): %.*s", (int) len, (int) len,
           buf);

    } else {
        dd("XXX one buffer only");

        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0) {
            return NGX_OK;
        }

        buf = b->pos;
        last = b->last;
    }

    for (p = buf; p < last; p++) {
        /* we need '=' after name, so drop one char from last */

        p = ngx_strlcasestrn(p, last - 1, arg_name, arg_len - 1);
        if (p == NULL) {
            return NGX_OK;
        }

        dd("found argument name, offset: %d", (int) (p - buf));

        if ((p == buf || *(p - 1) == '&') && *(p + arg_len) == '=') {
            v = p + arg_len + 1;
            dd("v = %d...", (int) (v - buf));

            dd("buf now (len %d): %.*s",
               (int) (last - v), (int) (last - v), v);

            p = ngx_strlchr(v, last, '&');
            if (p == NULL) {
                dd("& not found, pointing it to last...");
                p = last;

            } else {
                dd("found &, pointing it to %d...", (int) (p - buf));
            }

            if (multi) {
                s = ngx_array_push(array);
                if (s == NULL) {
                    return NGX_ERROR;
                }
                s->data = v;
                s->len = p - v;
                dd("array var:%.*s", (int) s->len, s->data);

            } else {
                value->data = v;
                value->len = p - v;
                dd("value: [%.*s]", (int) value->len, value->data);
                return NGX_OK;
            }
        }
    }

#if 0
    if (multi) {
        value->data = (u_char *) array;
        value->len = sizeof(ngx_array_t);
    }
#endif

    return NGX_OK;
}






// parse request body into json 

static ngx_int_t
ngx_http_set_form_input_json(ngx_http_request_t *r, ngx_str_t *res,
    ngx_http_variable_value_t *v)
{
    ngx_http_form_input_ctx_t           *ctx;
    ngx_int_t                            rc;

    dd_enter();

    dd("set default return value");
    ngx_str_set(res, "");

    /* dd("set default return value"); */

    if (r->done) {
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_form_input_module);

    if (ctx == NULL) {
        dd("ndk handler:null ctx");
        return NGX_OK;
    }

    if (!ctx->done) {
        dd("ctx not done");
        return NGX_OK;
    }

    rc = ngx_http_form_input_json(r, v->data, v->len, res, 0);

    return rc;
}

int
ngx_http_set_misc_escape_json_str_forked(char *dst, char *src, size_t size)
{
    ngx_uint_t                   n;

    static char hex[] = "0123456789abcdef";

    if (dst == NULL) {
        /* find the number of characters to be escaped */

        n = 0;

        while (size) {
            /* UTF-8 char has high bit of 1 */
            if ((*src & 0x80) == 0) {
                switch (*src) {
                case '\r':
                case '\n':
                case '\\':
                case '"':
                case '\f':
                case '\b':
                case '\t':
                    n++;
                    break;
                default:
                    if (*src < 32) {
                        n += sizeof("\\u00xx") - 2;
                    }

                    break;
                }
            }

            src++;
            size--;
        }

        return (uintptr_t) n;
    }

    while (size) {
        if ((*src & 0x80) == 0) {
            switch (*src) {
            case '\r':
                *dst++ = '\\';
                *dst++ = 'r';
                break;

            case '\n':
                *dst++ = '\\';
                *dst++ = 'n';
                break;

            case '\\':
                *dst++ = '\\';
                *dst++ = '\\';
                break;

            case '"':
                *dst++ = '\\';
                *dst++ = '"';
                break;

            case '\f':
                *dst++ = '\\';
                *dst++ = 'f';
                break;

            case '\b':
                *dst++ = '\\';
                *dst++ = 'b';
                break;

            case '\t':
                *dst++ = '\\';
                *dst++ = 't';
                break;

            default:
                if (*src < 32) { /* control chars */
                    *dst++ = '\\';
                    *dst++ = 'u';
                    *dst++ = '0';
                    *dst++ = '0';
                    *dst++ = hex[*src >> 4];
                    *dst++ = hex[*src & 0x0f];
                } else {
                    *dst++ = *src;
                }
                break;
            } /* switch */

            src++;

        } else {
            *dst++ = *src++;
        }

        size--;
    }

    return (uintptr_t) dst;
}

// push value into sorted array at correct spot 
// sorting is needed to serialize nested qs keys properly
int array_push_sorted(char *array[128], int size, char *string, int length) {
  int j, k;
  char *old;
  for (j = 0; j < size; j++ ) {
    old = array[j];
    int i = 0;
    // skip equal parts of keys
    for (; i < length; i++)
      if (string[i] != old[i])
        break;
    // compare strings, splice item into array
    if (string[i] < old[i]) {
      for (k = size; --k >= j;)
        array[k + 1] = array[k];
      break;
    }
  }
  array[j] = string;

  // return new length
  return size + 1;
}

// fills given string with nested json produced by parsing of qs
char *query_string_to_json(char *response, char *qs, int size) {
  int length = 0;
  char *array[512]; // max k: v pairs

  char *last = qs;
  char *p = qs;
  for (; p < qs + size; p++) {
    if (*p == '&' || p == qs + size - 1) {
      length = array_push_sorted(array, length, last, p - last - 1);
      last = p + 1;
    }

  }

  strcat(response, "{");

  int lastch = 0;
  char *finish, *start, *position, *previous;

  previous = NULL;

  int i = 0;
  for (; i < length; i++) {
    start = *(array + i);
    position = start;

    int separated = 0;
    int closed = 0;
    char *p = *(array + i);
    for (; p < qs + size; p++) {
      char *next = p;
      lastch = (p == qs + size - 1 || *next == '&' || *next == '=') ? 1 : 0;
      
      // found boundaries of a keyword (EOL, [ or ])
      if (*next == '[' || lastch) {
        finish = p;
        int prepended = 0;

        if (previous != NULL) {
          // Dont prepend context that matches with previous key
          int len = last - previous;
          int s = position - start;
          // check if previous key matches current key so far 
          if (strncmp(previous, start, s) == 0)
            if (!lastch && strncmp(previous, start, finish - start) == 0) {
              //fprintf(stdout, "Consider prepended: [%d %s] \n%s\n%s\n\n", s, next, previous, start);
              prepended = 1; 
            }

          // close all mismatching objects
          //fprintf(stdout, "LOL [%d %d]: %.*s\n",prepended, closed, 5, next );
          if (closed == 0 && prepended == 0) {
            closed = 1;
            char *m = last, *n = NULL;
            //fprintf(stdout, "Breaking [%d] \n%s\n%s\n\n", lastch, previous + s, position);
            for (; m >= previous + s; m--) {
              if (*m == '[') {
                for (n = m; *(n + 1) != ']';)
                  n++;
                if (m == n || ngx_atoi((u_char *) m + 1, n - m) != NGX_ERROR) {
                  strcat(response, "]\n");
                } else {
                  strcat(response, "}\n"); 
                }
              }
            }
          }

          // add comma
          if (!separated && closed) {
            separated = 1;
            strcat(response, ",");
          }
        }

        // prepend key
        if (!prepended) {
          char *fin = *(finish - 1) == ']' ? finish - 1 : finish;
          char *pos = *position == '[' ? position + 1 : position;

          int l = strlen(response);
          if (fin - pos == 0 || ngx_atoi((u_char *) pos, fin - pos) != NGX_ERROR) {// [] array accessor
            if (response[l - 1] == '\n' && response[l - 2] == '{')
              response[l - 2] = '[';
            if (lastch)
              strcat(response, "\"");
            else
              strcat(response, "{");

            prepended = 1;
          } else {
            strcat(response, "\"");
            strncpy(response + l + 1, pos, fin - pos);

            if (lastch)
              strcat(response, "\":\"");
          }

        }

        if (lastch) {
          // find value
          char *v = finish + 1;
          for (; v < qs + size; v++) {
            if (*v == '&' || *v == '=')
              break;
          }

          
          // need to escape quotes?
          int escape = ngx_http_set_misc_escape_json_str_forked(NULL, finish + 1, v - finish - 1);
          //fprintf(stdout, "got to escape %d\n", escape);

          int from = strlen(response);
          if (escape > 0) {
            ngx_http_set_misc_escape_json_str_forked(response + from, finish + 1, v - finish - 1);

          // append value
          } else {
            strncpy(response + from, finish + 1, v - finish - 1);
          }

          strcat(response, "\"\n");

          // remember path
          previous = start;
          last = position;

        } else {
          // prepend key
          if (!prepended) strcat(response, "\": {\n");
          position = finish + 1;
        }
      }
      if (lastch) break;


    }
  }
  // close all open objects
  char *m = finish, 
       *n = NULL;
  for (; m > previous; m--)
    if (*m == ']' || m == previous + 1) {
      for (n = m; (n > previous) && (*(n - 1) != '[');)
        n--;
      if (m == n || ngx_atoi((u_char *) n, m - n) != NGX_ERROR) {
        strcat(response, "]\n");
      } else {
        strcat(response, "}\n"); 
      }
    }
  return response;
}


/* serialize response as json
  (as k/v objects wrapped in outer array)*/
static ngx_int_t
ngx_http_form_input_json(ngx_http_request_t *r, u_char *arg_name, size_t arg_len,
    ngx_str_t *value, ngx_flag_t multi)
{
    u_char              *p, *last, *buf;
    ngx_chain_t         *cl;
    size_t               len = 0;
    ngx_array_t         *array = NULL;
    ngx_buf_t           *b;

    if (multi) {
        array = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
        if (array == NULL) {
            return NGX_ERROR;
        }
        value->data = (u_char *)array;
        value->len = sizeof(ngx_array_t);

    } else {
        ngx_str_set(value, "");
    }

    /* we read data from r->request_body->bufs */
    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        dd("empty rb or empty rb bufs");
        return NGX_OK;
    }

    if (r->request_body->bufs->next != NULL) {
        /* more than one buffer...we should copy the data out... */
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            b = cl->buf;

            if (b->in_file) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "form-input: in-file buffer found. aborted. "
                              "consider increasing your "
                              "client_body_buffer_size setting");

                return NGX_OK;
            }

            len += b->last - b->pos;
        }

        dd("len=%d", (int) len);

        if (len == 0) {
            return NGX_OK;
        }

        buf = ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = r->request_body->bufs; cl; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }

        dd("p - buf = %d, last - buf = %d", (int) (p - buf),
           (int) (last - buf));

        dd("copied buf (len %d): %.*s", (int) len, (int) len,
           buf);

    } else {
        dd("XXX one buffer only");

        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0) {
            return NGX_OK;
        }

        buf = b->pos;
        last = b->last;
    }


    char decoded[64000] = "";
    char serialized[64000] = "";
    ngx_memzero(serialized, 64000);

    //fprintf(stdout, "escaping %s\n ", buf);

    u_char *dst = (u_char *) &decoded;
    u_char *src = (u_char *) &decoded;


    // replace + to spaces
    int j = 0;
    for (; j < last - buf; j++) {
      if (buf[j] == '+')
        dst[j] = ' ';
      else
        dst[j] = buf[j];
    }


    ngx_unescape_uri(&dst, &src, last - buf, 0);
    *dst = '\0';


    
    query_string_to_json(serialized, decoded, strlen(decoded));
    // fprintf(stdout, "QS: %s\n", serialized);

    int size = strlen(serialized);
    char *response = ngx_pnalloc(r->pool, size + 1);
    memcpy(response, serialized, size + 1);


    value->data = (u_char *) response;
    value->len = strlen(response);
    value->data[value->len] = '\0';
    dd("value: [%.*s]", (int) value->len, value->data);
    return NGX_OK;

}



static char *
ngx_http_set_form_input_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ndk_set_var_t                            filter;
    ngx_str_t                               *value, s;
    u_char                                  *p;
    ngx_http_form_input_main_conf_t         *fmcf;

#if defined(nginx_version) && nginx_version >= 8042 && nginx_version <= 8053
    return "does not work with " NGINX_VER;
#endif

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_form_input_module);

    fmcf->used = 1;

    filter.type = NDK_SET_VAR_MULTI_VALUE;
    filter.size = 1;

    value = cf->args->elts;

    if ((value->len == sizeof("set_form_input_multi") - 1) &&
        ngx_strncmp(value->data, "set_form_input_multi", value->len) == 0)
    {
        dd("use ngx_http_form_input_multi");
        filter.func = (void *) ngx_http_set_form_input_multi;
    } else if ((value->len == sizeof("set_form_input_json") - 1) &&
        ngx_strncmp(value->data, "set_form_input_json", value->len) == 0)
    {
        dd("use ngx_http_form_input_json");
        filter.func = (void *) ngx_http_set_form_input_json;

    } else {
        filter.func = (void *) ngx_http_set_form_input;
    }

    value++;

    if (cf->args->nelts == 2) {
        p = value->data;
        p++;
        s.len = value->len - 1;
        s.data = p;

    } else if (cf->args->nelts == 3) {
        s.len = (value + 1)->len;
        s.data = (value + 1)->data;
    }

    return ndk_set_var_multi_value_core (cf, value,  &s, &filter);
}


/* register a new rewrite phase handler */
static ngx_int_t
ngx_http_form_input_init(ngx_conf_t *cf)
{

    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_form_input_main_conf_t *fmcf;

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_form_input_module);

    if (!fmcf->used) {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_form_input_handler;

    return NGX_OK;
}


/* an rewrite phase handler */
static ngx_int_t
ngx_http_form_input_handler(ngx_http_request_t *r)
{
    ngx_http_form_input_ctx_t       *ctx;
    ngx_str_t                        value;
    ngx_int_t                        rc;

    dd_enter();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input rewrite phase handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_form_input_module);

    if (ctx != NULL) {
        if (ctx->done) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http form_input rewrite phase handler done");

            return NGX_DECLINED;
        }

        return NGX_DONE;
    }

    if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT) {
        return NGX_DECLINED;
    }

    if (r->headers_in.content_type == NULL
        || r->headers_in.content_type->value.data == NULL)
    {
        dd("content_type is %p", r->headers_in.content_type);

        return NGX_DECLINED;
    }

    value = r->headers_in.content_type->value;

    dd("r->headers_in.content_length_n:%d",
       (int) r->headers_in.content_length_n);

    /* just focus on x-www-form-urlencoded */

    if (value.len < form_urlencoded_type_len
        || ngx_strncasecmp(value.data, (u_char *) form_urlencoded_type,
                           form_urlencoded_type_len) != 0)
    {
        dd("not application/x-www-form-urlencoded");
        return NGX_DECLINED;
    }

    dd("content type is application/x-www-form-urlencoded");

    dd("create new ctx");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_form_input_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* set by ngx_pcalloc:
     *      ctx->done = 0;
     *      ctx->waiting_more_body = 0;
     */

    ngx_http_set_ctx(r, ctx, ngx_http_form_input_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input start to read client request body");

    rc = ngx_http_read_client_request_body(r, ngx_http_form_input_post_read);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
        r->main->count--;
#endif

        return rc;
    }

    if (rc == NGX_AGAIN) {
        ctx->waiting_more_body = 1;

        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input has read the request body in one run");

    return NGX_DECLINED;
}


static void
ngx_http_form_input_post_read(ngx_http_request_t *r)
{
    ngx_http_form_input_ctx_t     *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http form_input post read request body");

    ctx = ngx_http_get_module_ctx(r, ngx_http_form_input_module);

    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    dd("count--");
    r->main->count--;
#endif

    dd("waiting more body: %d", (int) ctx->waiting_more_body);

    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;

        ngx_http_core_run_phases(r);
    }
}


static void *
ngx_http_form_input_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_form_input_main_conf_t    *fmcf;

    fmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_form_input_main_conf_t));
    if (fmcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      fmcf->used = 0;
     */

    return fmcf;
}
