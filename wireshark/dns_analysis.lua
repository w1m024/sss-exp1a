-- DNS analysis postdissector. Uses Wireshark's DNS decoding and TCP reassembly.
-- Load explicitly: tshark -X lua_script:wireshark/dns_analysis.lua -r capture.pcap
local proto = Proto("dns_analysis", "DNS query analysis")
local query_name = Field.new("dns.qry.name")
local response_code = Field.new("dns.flags.rcode")
local response_time = Field.new("dns.time")
local fields = {
    name = ProtoField.string("dns_analysis.query", "Query name"),
    length = ProtoField.uint16("dns_analysis.name_length", "Query name length", base.DEC),
    labels = ProtoField.uint16("dns_analysis.labels", "Label count", base.DEC),
    longest = ProtoField.uint16("dns_analysis.longest_label", "Longest label length", base.DEC),
    long_label = ProtoField.bool("dns_analysis.long_label", "Label exceeds configured threshold"),
    nxdomain = ProtoField.bool("dns_analysis.nxdomain", "Name does not exist (NXDOMAIN)"),
    milliseconds = ProtoField.double("dns_analysis.response_ms", "Response time (ms)"),
}
proto.fields = fields
local long_note = ProtoExpert.new("dns_analysis.long_label_note", "Long DNS label; inspect context before drawing conclusions", expert.group.PROTOCOL, expert.severity.NOTE)
proto.experts = { long_note }
proto.prefs.long_label = Pref.uint("Long label threshold", 40, "Labels longer than this threshold receive a note; this alone does not imply malicious traffic.")

function proto.dissector(buffer, pinfo, tree)
    local names = { query_name() }
    if #names == 0 then return end
    local root = tree:add(proto)
    for _, value in ipairs(names) do
        local text = tostring(value)
        local count, longest = 0, 0
        for label in text:gmatch("[^.]+") do
            count = count + 1
            if #label > longest then longest = #label end
        end
        local group = root:add(fields.name, text):set_generated()
        group:add(fields.length, #text):set_generated()
        group:add(fields.labels, count):set_generated()
        group:add(fields.longest, longest):set_generated()
        local is_long = longest > proto.prefs.long_label
        group:add(fields.long_label, is_long):set_generated()
        if is_long then group:add_proto_expert_info(long_note) end
    end
    local code = response_code()
    if code then root:add(fields.nxdomain, tonumber(tostring(code)) == 3):set_generated() end
    local elapsed = response_time()
    if elapsed then root:add(fields.milliseconds, tonumber(tostring(elapsed)) * 1000):set_generated() end
end

register_postdissector(proto)
