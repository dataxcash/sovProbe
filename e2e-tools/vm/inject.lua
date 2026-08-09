-- wrk inject.lua — TC-1 跨网注入 VM-1:8080，固定 4KB Body（触发 TRUNCATED 与不截断两类记录）
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
local body = string.rep("A", 4096)
function request()
    local id = math.random(1, 1000000000)
    return wrk.format("POST", "/api/orders/" .. id, {["Content-Length"]=tostring(#body)}, body)
end
