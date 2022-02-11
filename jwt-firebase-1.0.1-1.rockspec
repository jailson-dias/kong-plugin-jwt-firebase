package = "jwt-firebase"
version = "1.1.0"
source = {
  url = "https://github.com/jailson-dias/kong-plugin-jwt-firebase",
}
description = {
  summary = "This plugin allows Kong to verify JWT Firebase Token.",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["jwt-firebase.handler"] = "kong/plugins/jwt-firebase/handler.lua",
    ["jwt-firebase.schema"]  = "kong/plugins/jwt-firebase/schema.lua"
  }
}

