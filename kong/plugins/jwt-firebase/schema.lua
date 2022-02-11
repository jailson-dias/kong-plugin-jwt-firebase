local typedefs = require "kong.db.schema.typedefs"


return {
  name = "jwt-firebase",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          {
            uri_param_names = {
              type = "set",
              elements = { type = "string" },
              default = { "jwt" },
            },
          },
          {
            cookie_names = {
              type = "set",
              elements = { type = "string" },
              default = {}
            },
          },
	        { uid_header_key = { type = "string", default = "x-uid" }, },
          {
            claims_to_verify = {
              type = "set",
              default = { "exp" },
              elements = {
                type = "string",
                one_of = { "exp", "nbf" },
              },
            },
          },
          {
            maximum_expiration = {
              type = "number",
              default = 0,
              between = { 0, 31536000 },
            },
          },
	        { project_id = { type = "string", default = "fb-project" }, },
          { unauthorized_status_code = { type = "number", default = 401 }, },
          {
            unauthorized_messages = {
              type = "record",
              fields = {
                { unauthorized = { type = "string", default = "Unauthorized" }, },
                { multiple_tokens = { type = "string", default = "Unauthorized" }, },
                { unrecognizable_token = { type = "string", default = "Unauthorized" }, },
                { error_decoding_token = { type = "string", default = "Unauthorized" }, },
                { invalid_algorithm = { type = "string", default = "Unauthorized" }, },
                { invalid_iss = { type = "string", default = "Unauthorized" }, },
                { invalid_aud = { type = "string", default = "Unauthorized" }, },
                { token_has_expired = { type = "string", default = "Unauthorized" }, },
                { empty_sub = { type = "string", default = "Unauthorized" }, },
                { invalid_signature = { type = "string", default = "Unauthorized" }, },
              },
            },
          },
          { unexpected_error_status_code = { type = "number", default = 500 }, },
          { unexpected_error_message = { type = "string", default = "An unexpected error has occurred" }, },
        },
      },
    },
  },
}
