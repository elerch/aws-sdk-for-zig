#include <aws/auth/signing_config.h>
#include <aws/common/date_time.h>

#include "bitfield-workaround.h"

extern void *new_aws_signing_config(
    struct aws_allocator *allocator,
    const struct bitfield_workaround_aws_signing_config_aws *config) {
  struct aws_signing_config_aws *new_config = aws_mem_acquire(allocator, sizeof(struct aws_signing_config_aws));

  new_config->algorithm                       = config->algorithm;
  new_config->config_type                     = config->config_type;
  new_config->signature_type                  = config->signature_type;
  new_config->region                          = config->region;
  new_config->service                         = config->service;
  new_config->should_sign_header              = config->should_sign_header;
  new_config->should_sign_header_ud           = config->should_sign_header_ud;
  new_config->flags.use_double_uri_encode     = config->flags.use_double_uri_encode;
  new_config->flags.should_normalize_uri_path = config->flags.should_normalize_uri_path;
  new_config->flags.omit_session_token        = config->flags.omit_session_token;
  new_config->signed_body_value               = config->signed_body_value;
  new_config->signed_body_header              = config->signed_body_header;
  new_config->credentials                     = config->credentials;
  new_config->credentials_provider            = config->credentials_provider;
  new_config->expiration_in_seconds           = config->expiration_in_seconds;

  aws_date_time_init_now(&new_config->date);

  return new_config;
}

extern FILE *get_std_err() {
  return stderr;
}
