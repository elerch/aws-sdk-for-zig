#ifndef ZIG_AWS_BITFIELD_WORKAROUND_H
#define ZIG_AWS_BITFIELD_WORKAROUND_H

#include <aws/auth/auth.h>
#include <aws/auth/signing_config.h>



// Copied verbatim from https://github.com/awslabs/aws-c-auth/blob/main/include/aws/auth/signing_config.h#L127-L241
// However, the flags has changed to uint32_t without bitfield annotations
// as Zig does not support them yet. See https://github.com/ziglang/zig/issues/1499
// We've renamed as well to make clear what's going on
//
// Signing date is also somewhat problematic, so we removed it and it is
// part of the c code

/*
 * Put all flags in here at the end.  If this grows, stay aware of bit-space overflow and ABI compatibilty.
 */
struct bitfield_workaround_aws_signing_config_aws_flags {
    /**
     * We assume the uri will be encoded once in preparation for transmission.  Certain services
     * do not decode before checking signature, requiring us to actually double-encode the uri in the canonical
     * request in order to pass a signature check.
     */
    uint32_t use_double_uri_encode;

    /**
     * Controls whether or not the uri paths should be normalized when building the canonical request
     */
    uint32_t should_normalize_uri_path;

    /**
     * Controls whether "X-Amz-Security-Token" is omitted from the canonical request.
     * "X-Amz-Security-Token" is added during signing, as a header or
     * query param, when credentials have a session token.
     * If false (the default), this parameter is included in the canonical request.
     * If true, this parameter is still added, but omitted from the canonical request.
     */
    uint32_t omit_session_token;
};

/**
 * A configuration structure for use in AWS-related signing.  Currently covers sigv4 only, but is not required to.
 */
struct bitfield_workaround_aws_signing_config_aws {

    /**
     * What kind of config structure is this?
     */
    enum aws_signing_config_type config_type;

    /**
     * What signing algorithm to use.
     */
    enum aws_signing_algorithm algorithm;

    /**
     * What sort of signature should be computed?
     */
    enum aws_signature_type signature_type;

    /**
     * The region to sign against
     */
    struct aws_byte_cursor region;

    /**
     * name of service to sign a request for
     */
    struct aws_byte_cursor service;

    /**
     * Raw date to use during the signing process.
     */
    // struct aws_date_time date;

    /**
     * Optional function to control which headers are a part of the canonical request.
     * Skipping auth-required headers will result in an unusable signature.  Headers injected by the signing process
     * are not skippable.
     *
     * This function does not override the internal check function (x-amzn-trace-id, user-agent), but rather
     * supplements it.  In particular, a header will get signed if and only if it returns true to both
     * the internal check (skips x-amzn-trace-id, user-agent) and this function (if defined).
     */
    aws_should_sign_header_fn *should_sign_header;
    void *should_sign_header_ud;

    /*
     * Put all flags in here at the end.  If this grows, stay aware of bit-space overflow and ABI compatibilty.
     */
    struct bitfield_workaround_aws_signing_config_aws_flags flags;

    /**
     * Optional string to use as the canonical request's body value.
     * If string is empty, a value will be calculated from the payload during signing.
     * Typically, this is the SHA-256 of the (request/chunk/event) payload, written as lowercase hex.
     * If this has been precalculated, it can be set here. Special values used by certain services can also be set
     * (e.g. "UNSIGNED-PAYLOAD" "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" "STREAMING-AWS4-HMAC-SHA256-EVENTS").
     */
    struct aws_byte_cursor signed_body_value;

    /**
     * Controls what body "hash" header, if any, should be added to the canonical request and the signed request:
     *   AWS_SBHT_NONE - no header should be added
     *   AWS_SBHT_X_AMZ_CONTENT_SHA256 - the body "hash" should be added in the X-Amz-Content-Sha256 header
     */
    enum aws_signed_body_header_type signed_body_header;

    /*
     * Signing key control:
     *
     *   (1) If "credentials" is valid, use it
     *   (2) Else if "credentials_provider" is valid, query credentials from the provider and use the result
     *   (3) Else fail
     *
     */

    /**
     * AWS Credentials to sign with.
     */
    const struct aws_credentials *credentials;

    /**
     * AWS credentials provider to fetch credentials from.
     */
    struct aws_credentials_provider *credentials_provider;

    /**
     * If non-zero and the signing transform is query param, then signing will add X-Amz-Expires to the query
     * string, equal to the value specified here.  If this value is zero or if header signing is being used then
     * this parameter has no effect.
     */
    uint64_t expiration_in_seconds;
};



extern void *new_aws_signing_config(struct aws_allocator *allocator, const struct bitfield_workaround_aws_signing_config_aws *config);
extern FILE *get_std_err();
#endif
