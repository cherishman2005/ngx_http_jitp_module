#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
	ngx_str_t                    upstream_location;
	size_t                       buffer_size;
} ngx_http_jitp_loc_conf_t;

typedef struct{
	ngx_http_request_t          *r;
	ngx_http_jitp_loc_conf_t    *conf;

	// temporary completion state
	ngx_http_upstream_t         *upstream;
	ngx_int_t                    error_code;
	ngx_flag_t                   dont_send_header;
	
	size_t                       length;
	ngx_buf_t                    read_buffer;

	unsigned                     seen_last_for_subreq:1; /* used by body filter */
} ngx_http_jitp_ctx_t;

static ngx_int_t
ngx_http_jitp_handler(ngx_http_request_t *r);

static void
ngx_http_jitp_wev_handler(ngx_http_request_t * r);

static char*
ngx_http_jitp(ngx_conf_t *cf ,ngx_command_t *cmd ,void *conf);

static ngx_int_t
ngx_http_jitp_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc);

static ngx_int_t
ngx_http_jitp_adjust_subrequest(ngx_http_request_t *sr);

static void *
ngx_http_jitp_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_jitp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t
ngx_http_jitp_init_parsers(ngx_conf_t *cf);

ngx_int_t
ngx_http_jitp_remote_request_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_jitp_async_http_read(ngx_http_jitp_ctx_t *ctx);

static ngx_int_t
ngx_http_jitp_start_processing_media_file(ngx_http_jitp_ctx_t *ctx);

static ngx_int_t
ngx_http_jitp_run_state_machine(ngx_http_jitp_ctx_t *ctx);

static int 
ngx_debug_write_file(const char *buf, int len);

static ngx_command_t  ngx_http_jitp_commands[] =
{
    {  ngx_string("jitp"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
       ngx_http_jitp,
       NGX_HTTP_LOC_CONF_OFFSET,
       0,
       NULL },

	{  ngx_string("jitp_upstream_location"),
	   NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
	   ngx_conf_set_str_slot,
	   NGX_HTTP_LOC_CONF_OFFSET,
	   offsetof(ngx_http_jitp_loc_conf_t, upstream_location),
	   NULL },

	{  ngx_string("jitp_buffer"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
       ngx_conf_set_size_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_jitp_loc_conf_t, buffer_size),
       NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_jitp_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_jitp_init_parsers,               /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_jitp_create_loc_conf,            /* create location configuration */
    ngx_http_jitp_merge_loc_conf              /* merge location configuration */
};

ngx_module_t  ngx_http_jitp_module = {
    NGX_MODULE_V1,
    &ngx_http_jitp_module_ctx,             /* module context */
    ngx_http_jitp_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char*
ngx_http_jitp(ngx_conf_t *cf,ngx_command_t*cmd,void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_jitp_handler;

    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_jitp_post_subrequest(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
	ngx_http_jitp_ctx_t         *ctx;
    ngx_http_request_t          *pr = r->parent;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "ngx_http_jitp_post_subrequest");
		
	// make sure we are not called twice for the same request
	r->post_subrequest = NULL;
	
    ctx = ngx_http_get_module_ctx(pr, ngx_http_jitp_module);
	if (ctx == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_jitp_post_subrequest: unexpected, context is null");
		return NGX_ERROR;
	}

	ctx->upstream = r->upstream;
	ctx->error_code = rc;

    pr->headers_out.status = r->headers_out.status;	
    pr->write_event_handler = ngx_http_jitp_wev_handler;
	
	// work-around issues in nginx's event module (from echo-nginx-module)
	if (r != r->connection->data
		&& r->postponed
		&& (r->main->posted_requests == NULL
		|| r->main->posted_requests->request != pr))
	{
#if defined(nginx_version) && nginx_version >= 8012
		ngx_http_post_request(pr, NULL);
#else
		ngx_http_post_request(pr);
#endif
	}

    return NGX_OK;
}

static void
ngx_http_jitp_wev_handler(ngx_http_request_t * r)
{
	ngx_int_t                 rc;
	ngx_http_upstream_t      *u;
	ngx_http_jitp_ctx_t      *ctx;
	ngx_buf_t                *buf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "ngx_http_jitp_wev_handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_jitp_module);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
		
	// get the completed upstream
	u = ctx->upstream;
	if (u == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_jitp_wev_handler: unexpected, upstream is null");
		return;
	}

	// code taken from echo-nginx-module to work around nginx subrequest issues
	if (r == r->connection->data && r->postponed) {

		if (r->postponed->request) {
			r->connection->data = r->postponed->request;

#if defined(nginx_version) && nginx_version >= 8012
			ngx_http_post_request(r->postponed->request, NULL);
#else
			ngx_http_post_request(r->postponed->request);
#endif

		} else {
			ngx_http_output_filter(r, NULL);
		}
	}

	// get the final error code
	rc = ctx->error_code;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "ngx_http_jitp_wev_handler, rc = %i", rc);

	if (rc == NGX_OK) {
		switch (u->headers_in.status_n) {
		case NGX_HTTP_OK:
		case NGX_HTTP_PARTIAL_CONTENT:
			if (u->length != 0 && u->length != -1 && !u->headers_in.chunked && !ctx->seen_last_for_subreq) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"ngx_http_jitp_wev_handler: upstream connection was closed with %O bytes left to read", u->length);
				rc = NGX_HTTP_BAD_GATEWAY;
			}
			break;
			
		case NGX_HTTP_BAD_REQUEST:
		case NGX_HTTP_NOT_FOUND:
			rc = u->headers_in.status_n;
			u->buffer.last = u->buffer.pos;
			break;

		case NGX_HTTP_RANGE_NOT_SATISFIABLE:
			// ignore this error, treat it like a successful read with empty body
			rc = NGX_OK;
			u->buffer.last = u->buffer.pos;
			break;

		default:
			if (u->headers_in.status_n != 0) {
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"ngx_http_jitp_wev_handler: upstream returned a bad status %ui", u->headers_in.status_n);
			} else {
				ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
					"ngx_http_jitp_wev_handler: failed to get upstream status");
			}
			rc = NGX_HTTP_BAD_GATEWAY;
			break;
		}
	}
	else if (rc == NGX_ERROR)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_jitp_wev_handler: got error -1, changing to 502");
		rc = NGX_HTTP_BAD_GATEWAY;
	}
	
	if (rc == NGX_HTTP_BAD_GATEWAY 
		|| rc == NGX_HTTP_BAD_REQUEST
	    || rc == NGX_HTTP_NOT_FOUND)	
	{
        ngx_http_finalize_request(r, rc);
		return;
    }	

    buf = &ctx->read_buffer;

    //debug-test
	ngx_debug_write_file(buf->pos, buf->last - buf->pos);
    
    // todo
    /*
    * process  m3u8 change and output filter
    */

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, buf->last - buf->pos);
    b->last = ngx_cpymem(b->last, buf->pos, buf->last - buf->pos);
    b->last_buf = 1;
	b->last_in_chain = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;
	//ctx->upstream = NULL;
		
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return;
    }
	
    rc = ngx_http_output_filter(r, &out);

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_jitp_handler(ngx_http_request_t * r)
{
    ngx_int_t                       rc;
	ngx_http_jitp_ctx_t            *ctx;
	ngx_http_post_subrequest_t     *psr;
	ngx_http_request_t             *sr;
	ngx_http_jitp_loc_conf_t       *conf;
	ngx_str_t                       sub_prefix;
	ngx_str_t                       sub_location;
	ngx_str_t                      *url_args = NULL;
	ngx_uint_t                      flags;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_jitp_handler: started");	


	if (r->method == NGX_HTTP_OPTIONS) {
	    //to do;
	}

	// we respond to 'GET' and 'HEAD' requests only
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"ngx_http_vod_handler: unsupported method %ui", r->method);
		rc = NGX_HTTP_NOT_ALLOWED;
		goto jitp_done;
	}

	// discard request body, since we don't need it here
	rc = ngx_http_discard_request_body(r);
	if (rc != NGX_OK) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_vod_handler: ngx_http_discard_request_body failed %i", rc);
		goto jitp_done;
	}

	// initialize the context
	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jitp_ctx_t));
	if (ctx == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_jitp_handler: ngx_pcalloc failed");
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		goto jitp_done;
	}

	ngx_http_set_ctx(r, ctx, ngx_http_jitp_module);

	rc = ngx_http_jitp_remote_request_handler(r);
	
jitp_done:
	
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "ngx_http_jitp_handler: done");

	return rc;
}

ngx_int_t
ngx_http_jitp_remote_request_handler(ngx_http_request_t *r)
{
	ngx_http_jitp_ctx_t *ctx;
	ngx_int_t rc;

	ctx = ngx_http_get_module_ctx(r, ngx_http_jitp_module);
    ctx->r = r;

	rc = ngx_http_jitp_start_processing_media_file(ctx);
	if (rc != NGX_AGAIN && rc != NGX_DONE && rc != NGX_OK)
	{
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"ngx_http_jitp_remote_request_handler failed %i", rc);
	}

	return rc;
}

static ngx_int_t
ngx_http_jitp_start_processing_media_file(ngx_http_jitp_ctx_t *ctx)
{
	return ngx_http_jitp_run_state_machine(ctx);
}


static ngx_int_t
ngx_http_jitp_run_state_machine(ngx_http_jitp_ctx_t *ctx)
{
	ngx_int_t rc;

	rc = ngx_http_jitp_async_http_read(ctx);

	
	return NGX_OK;
}

static ngx_int_t
ngx_http_jitp_async_http_read(ngx_http_jitp_ctx_t *ctx)
{
    ngx_int_t                       rc;
	ngx_http_post_subrequest_t     *psr;
	ngx_http_request_t             *sr;
	ngx_http_jitp_loc_conf_t       *conf;
	ngx_str_t                       sub_prefix;
	ngx_str_t                       sub_location;
	ngx_str_t                      *url_args = NULL;
	ngx_uint_t                      flags;
	ngx_http_request_t             *r;

    r = ctx->r;
	r->root_tested = !r->error_page;
	r->allow_ranges = 1;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_jitp_post_subrequest;
    psr->data = ctx;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_jitp_module);

	if (conf->upstream_location.len == 0) {
        return NGX_ERROR;
    }

    sub_prefix = conf->upstream_location;

    sub_location.len = sub_prefix.len + r->uri.len;
    sub_location.data = ngx_palloc(r->pool, sub_location.len);
    ngx_snprintf(sub_location.data, sub_location.len,
                 "%V%V", &sub_prefix, &r->uri);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
               "ngx_http_jitp_handler, sub_location:\"%V\", args:\"%V\"", &sub_location, &r->args);	

    if (r->args.len > 0) {
		url_args = &r->args;
    }

	//flags = NGX_HTTP_SUBREQUEST_WAITED | NGX_HTTP_SUBREQUEST_IN_MEMORY;
	flags = 0;
    rc = ngx_http_subrequest(r, &sub_location, url_args, &sr, psr, flags);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

	sr->method = NGX_HTTP_GET;

	rc = ngx_http_jitp_adjust_subrequest(sr);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
	
	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		"ngx_http_jitp_handler: completed successfully sr=%p", sr);

    return NGX_AGAIN;
}




static ngx_int_t
ngx_http_jitp_adjust_subrequest(ngx_http_request_t *sr)
{
    ngx_http_core_main_conf_t   *cmcf;
    ngx_http_request_t          *r;

    /* we do not inherit the parent request's variables */
    cmcf = ngx_http_get_module_main_conf(sr, ngx_http_core_module);

    r = sr->parent;

    sr->header_in = r->header_in;

    /* XXX work-around a bug in ngx_http_subrequest */
    if (r->headers_in.headers.last == &r->headers_in.headers.part) {
        sr->headers_in.headers.last = &sr->headers_in.headers.part;
    }

    sr->variables = ngx_pcalloc(sr->pool, cmcf->variables.nelts
                                * sizeof(ngx_http_variable_value_t));

    if (sr->variables == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_jitp_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_jitp_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jitp_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
	conf->buffer_size = NGX_CONF_UNSET_SIZE;
	
    return conf;
}

static char *
ngx_http_jitp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_jitp_loc_conf_t *prev = parent;
	ngx_http_jitp_loc_conf_t *conf = child;
	
    ngx_conf_merge_str_value(conf->upstream_location, prev->upstream_location, "");
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              20 * 1024 * 1024);

    return NGX_CONF_OK;
}

static int 
ngx_debug_write_file(const char *buf, int len)
{
	int fd, size;
	static int i = 0;
	char file_name[256] = {0};
	
	i++;
	sprintf(file_name, "/home/jitp/video_test/%d.ts", i);
	fd = open(file_name, O_CREAT|O_TRUNC|O_RDWR, 0666);
	if (fd < 0) {
	    printf("open error\n");
		return -1;
	}

	size = write(fd, buf, len);
	if (size < 0) {
	    printf("open error\n");
		return -1;
	}

	return 0;
}


static ngx_int_t
ngx_http_jitp_add_copy_chain(ngx_http_request_t *r, ngx_chain_t *in, ngx_int_t *eof);

static void
ngx_http_jitp_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;

static ngx_int_t
ngx_http_jitp_subrequest_header_filter(ngx_http_request_t *r)
{
    off_t                          len;
    ngx_http_jitp_ctx_t           *pr_ctx;
    ngx_http_jitp_loc_conf_t      *conf;
	ngx_http_request_t            *pr = r->parent;

	// if the request is not a child of a vod request, ignore
	if (pr == NULL || pr->header_sent || ngx_http_get_module_ctx(pr, ngx_http_jitp_module) == NULL) {
		return ngx_http_next_header_filter(r);
	}

    conf = ngx_http_get_module_loc_conf(r, ngx_http_jitp_module);
	
    if (conf == NULL
        || r->header_only
        || (r->method & NGX_HTTP_HEAD))
    {
        return ngx_http_next_header_filter(r);
    }

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "jitp subrequest filter: too big response: %O", len);

        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

	// if the request is not a vod request or it's in memory, ignore
	pr_ctx = ngx_http_get_module_ctx(pr, ngx_http_jitp_module);
	if (pr_ctx == NULL) {
		return ngx_http_next_header_filter(r);
	}

    if (len == -1) {
        pr_ctx->length = conf->buffer_size;

    } else {
        pr_ctx->length = (size_t) len;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_jitp_subrequest_header_filter, ctx length = %d", pr_ctx->length);

	if (r->headers_out.status != 0) {
		// send the parent request headers
		//pr->headers_out = r->headers_out;
	} else {
		// no status code, this can happen in case the proxy module got an invalid status line
		//	and assumed it's HTTP/0.9, just don't send any header and close the connection when done
		pr_ctx->dont_send_header = 1;
		pr->keepalive = 0;
	}

    /* force subrequest response body buffer in memory */
    r->filter_need_in_memory = 1;
    r->header_sent = 1;

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_jitp_subrequest_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                      rc;
    off_t                          len;
	ngx_int_t                      eof = 0;
    ngx_http_jitp_ctx_t           *pr_ctx;
    ngx_http_jitp_loc_conf_t      *conf;
	ngx_http_request_t            *pr = r->parent;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, NULL);
    }

	// if the request is not a child of a vod request, ignore
	if (pr == NULL || pr->header_sent || ngx_http_get_module_ctx(pr, ngx_http_jitp_module) == NULL) {
		return ngx_http_next_body_filter(r, in);
	}

    pr_ctx = ngx_http_get_module_ctx(pr, ngx_http_jitp_module);
    if (pr_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_jitp_subrequest_body_filter, uri "
                   "\"%V\"", &r->uri);

    rc = ngx_http_jitp_add_copy_chain(pr, in, &eof);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (eof) {
        pr_ctx->seen_last_for_subreq = 1;
    }

	if (pr_ctx->seen_last_for_subreq == 1) {
		//ngx_debug_write_file(pr_ctx->read_buffer.pos, 
	    //                     pr_ctx->read_buffer.last - pr_ctx->read_buffer.pos);
	}

    ngx_http_jitp_discard_bufs(r->pool, in);

    return NGX_OK;
}

ngx_int_t
ngx_http_jitp_subrequest_init(ngx_conf_t *cf)
{
	ngx_http_next_header_filter = ngx_http_top_header_filter;
	ngx_http_top_header_filter = ngx_http_jitp_subrequest_header_filter;

	ngx_http_next_body_filter = ngx_http_top_body_filter;
	ngx_http_top_body_filter = ngx_http_jitp_subrequest_body_filter;

	return NGX_OK;
}


static ngx_int_t
ngx_http_jitp_init_parsers(ngx_conf_t *cf)
{
	ngx_int_t rc;

	rc = ngx_http_jitp_subrequest_init(cf);
	if (rc != NGX_OK)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"failed to initialize hide headers hash %i", rc);
		return NGX_ERROR;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_jitp_add_copy_chain(ngx_http_request_t *r, ngx_chain_t *in, ngx_int_t *eof)
{
    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_jitp_ctx_t          *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_jitp_module);

	*eof = 0;

    if (ctx->read_buffer.pos == NULL) {
        ctx->read_buffer.pos = ngx_palloc(r->pool, ctx->length);
        if (ctx->read_buffer.pos == NULL) {
            return NGX_ERROR;
        }
		ctx->read_buffer.start = ctx->read_buffer.pos;
		ctx->read_buffer.end = ctx->read_buffer.start + ctx->length;

        ctx->read_buffer.last = ctx->read_buffer.pos;
    }

    p = ctx->read_buffer.last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "jitp buf: %uz", size);

        rest = ctx->read_buffer.pos + ctx->length - p;

        if (size > rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "jitp filter: too big response, size = %i, rest = %i, ctx->length = %i", 
                          size, rest, ctx->length);
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_in_chain || b->last_buf) {
            ctx->read_buffer.last = p;
			*eof = 1;
            //return NGX_OK;
        }
    }

    ctx->read_buffer.last = p;

    return NGX_OK;
}

static void
ngx_http_jitp_discard_bufs(ngx_pool_t *pool, ngx_chain_t *in)
{
    ngx_chain_t         *cl;

    for (cl = in; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
        cl->buf->file_pos = cl->buf->file_last;
    }
}

