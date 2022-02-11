local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local openssl_pkey = require "openssl.pkey"


local shm = "/dev/shm/kong.jwt-firebase.pubkey"
local kong = kong
local type = type
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local ngx_set_header = ngx.req.set_header

local JwtHandler = {}


JwtHandler.PRIORITY = 70
JwtHandler.VERSION = "1.0.0"

--- Grab a public key from google api by the kid value
-- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
-- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response
-- from that endpoint to know when to refresh the public keys.
local function grab_public_key_bykid(t_kid)
  kong.log.debug("Grabbing pubkey from google")
  local google_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  local magic = " | cut -d \"\\\"\" -f4- | sed 's/\\\\n/\\n/g\' | sed 's/\"//g' | openssl x509 -pubkey -noout"
  local cmd = "curl -s " .. google_url .. " | grep -i " .. t_kid .. magic

  local cmd_handle = io.popen(cmd)
  local public_key = cmd_handle:read("*a")
  cmd_handle:close()

  return public_key
end


--- Push public key into /dev/shm
local function push_public_key_into_file(publickey, dir)
  kong.log.debug("Push public key into file: "  .. dir)
  local cmd = "echo -n \"" .. publickey .. "\" > " .. shm

  local cmd_handle, err = io.popen(cmd)
  if not cmd_handle then
    cmd_handlel:close()
    return false
  end
  cmd_handle:close()

  kong.log.debug("Public key saved to file successfully")
  return true
end

--- Get the public key from /dev/shm
local function get_public_key_from_file(dir)
  kong.log.debug("Getting public key from file: " .. dir)
  local file, err = io.open(dir, "r")
  if not file then
    kong.log.debug("Public key not found")
    return nil
  end
  io.input(file)
  local content = io.read("*a")
  io.close(file)
  return content
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
  local args = kong.request.get_query()
  for _, v in ipairs(conf.uri_param_names) do
    if args[v] then
      return args[v]
    end
  end

  local var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local cookie = var["cookie_" .. v]
    if cookie and cookie ~= "" then
      return cookie
    end
  end

  local authorization_header = kong.request.get_header("authorization")
  if authorization_header then
    kong.log.debug("Authorization header found, getting token")

    local m, err = re_match(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not m then
      kong.log.debug("Token found, but isnt a Bearer token")
      return authorization_header
    end

    local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      kong.log.debug("Bearer token not found")
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      kong.log.debug("Bearer token not found")
      return nil, err
    end

    if m and #m > 0 then
      kong.log.debug("Bearer token found, returning it")
      return m[1]
    end
  end
end


--- do_authentication is to verify JWT firebase token
---   ref to: https://firebase.google.com/docs/auth/admin/verify-id-tokens
local function do_authentication(conf)
  local token, err = retrieve_token(conf)
  if err then
    kong.log.err("Error retrieving token: " .. tostring(err))
    return kong.response.exit(conf.unexpected_error_status_code, { message = conf.unexpected_error_message })
  end

  local token_type = type(token)
  if token_type ~= "string" then
    if token_type == "nil" then
      kong.log.debug("Token not provided")
      return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.unauthorized }

    elseif token_type == "table" then
      kong.log.debug("Multiple tokens provided")
      return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.multiple_tokens }

    else
      kong.log.debug("Unrecognizable token")
      return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.unrecognizable_token }
    end
  end

  -- Decode token
  local jwt, err = jwt_decoder:new(token)
  if err then
    kong.log.info("Error decoding token: " .. tostring(err))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.error_decoding_token }
  end

  local claims = jwt.claims
  local header = jwt.header

  -- Verify Header
  -- -- Verify "alg"
  local hd_alg = jwt.header.alg
  if not hd_alg or hd_alg ~= "RS256" then
    kong.log.info("The token was encoded with an invalid algorithm: " .. tostring(hd_alg))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.invalid_algorithm }
  end

  -- Verify Payload
  -- -- Verify "iss"
  local pl_iss = jwt.claims.iss
  local conf_iss = "https://securetoken.google.com/" .. conf.project_id
  if not pl_iss or pl_iss ~= conf_iss then
    kong.log.info("The token was encoded with an invalid iss: " .. tostring(pl_iss))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.invalid_iss }
  end

  -- -- Verify the "aud"
  local pl_aud = jwt.claims.aud
  if not pl_aud or pl_aud ~= conf.project_id then
    kong.log.info("The token was encoded with an invalid aud: " .. tostring(pl_aud))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.invalid_aud }
  end

  -- -- Verify the "exp"
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    kong.log.info("The token exp has errors: " .. tostring(errors))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.token_has_expired }
  end

  -- -- Verify the "exp" with "maximum_expiration" value
  if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
    local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
    if not ok then
      kong.log.info("The token has expired: " .. tostring(errors))
      return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.token_has_expired }
    end
  end

  -- -- Verify the "sub" must be non-empty
  local pl_sub  = jwt.claims.sub
  if not pl_sub then
    kong.log.info("The token was encoded with an empty sub: " .. tostring(pl_sub))
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.empty_sub }
  end

  -- -- Pud user-id into request header
  ngx_set_header(conf.uid_header_key, pl_sub)

  -- Finally -- Verify the signature
  -- Finally, ensure that the ID token was signed by the private key corresponding to the token's kid claim.
  -- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com
  -- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response
  -- from that endpoint to know when to refresh the public keys.
  -- Now verify the JWT signature
  local kid = jwt.header.kid

  -- -- Get public key in memory file
  -- -- -- if it is invalied or empty
  -- -- -- -- grabs a new public key from google api
  -- -- -- -- push this key into memory file
  -- -- -- -- assign this key to public_key
  local public_key = get_public_key_from_file(shm)
  if not pcall(openssl_pkey.new, public_key) or public_key == nil then
    kong.log.info("Public key in a file is empty or invalid")

    local t_public_key = grab_public_key_bykid(kid)
    local ok, err = push_public_key_into_file(t_public_key, shm)
    if not ok then
      kong.log.crit("Failed to push a new publish key into SHM dir")
    end
    public_key = t_public_key
  end

  -- -- By using jwt lib to verify signature
  -- -- If failed
  -- -- -- grab a new public key from the google api
  -- -- -- store this public key into memory file if it verifies  successful at 2nd time
  if not jwt:verify_signature(public_key) then
    local t_public_key = grab_public_key_bykid(kid)
    if jwt:verify_signature(t_public_key) then
      local ok, err = push_public_key_into_file(t_public_key, shm)
      if not ok then
        kong.log.crit("Failed to push a new publish key into SHM dir")
      end
      return true
    end
    return false, { status = conf.unauthorized_status_code, message = conf.unauthorized_messages.invalid_signature }
  end
  return true
end


function JwtHandler:access(conf)
  kong.log.debug("Starting access process")
  local ok, err = do_authentication(conf)
  if not ok then
    return kong.response.exit(err.status, err.errors or { message = err.message })
  end
  kong.log.debug("Access process finished successfully")
end

return JwtHandler
